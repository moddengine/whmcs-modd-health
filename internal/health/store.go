package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }

type PendingNotification struct {
	ServiceID int64
	ProductID int64
	Domain    string
	Profile   string
	Type      string
	Result    SiteResult
}

func OpenDatabase(config DatabaseConfig) (*sql.DB, error) {
	dsn := mysql.NewConfig()
	dsn.User = config.Username
	dsn.Passwd = config.Password
	dsn.Net = config.Network
	if config.Network == "unix" {
		dsn.Addr = config.Socket
	} else {
		dsn.Addr = net.JoinHostPort(config.Host, fmt.Sprint(config.Port))
	}
	dsn.DBName = config.Name
	dsn.ParseTime = true
	dsn.Loc = time.UTC
	dsn.Timeout = 10 * time.Second
	dsn.ReadTimeout = 15 * time.Second
	dsn.WriteTimeout = 15 * time.Second
	switch config.TLS {
	case "preferred":
		dsn.TLSConfig = "preferred"
	case "required":
		dsn.TLSConfig = "true"
	default:
		dsn.TLSConfig = "false"
	}
	db, err := sql.Open("mysql", dsn.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	return db, nil
}

func (s Store) Save(ctx context.Context, site Site, result SiteResult) (Transition, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return Transition{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Transition{}, err
	}
	defer tx.Rollback()
	previous, exists, err := loadState(ctx, tx, site.ServiceID)
	if err != nil {
		return Transition{}, err
	}
	transition := ApplyObservation(previous, result.Healthy, result.CheckedAt)
	state := transition.State
	if exists {
		_, err = tx.ExecContext(ctx, `UPDATE mod_modd_health_state SET
            client_id=?, product_id=?, domain=?, profile=?, stable_state=?, observed_state=?,
            consecutive_count=?, checks_json=?, first_failure_at=?, confirmed_failure_at=?,
            last_checked_at=?, updated_at=?, pending_notification=? WHERE service_id=?`,
			site.ClientID, site.ProductID, site.Domain, site.Profile, state.Stable, state.Observed,
			state.Consecutive, string(data), state.FirstFailureAt, state.ConfirmedFailureAt,
			result.CheckedAt, result.CheckedAt, nullableString(state.PendingNotification), site.ServiceID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO mod_modd_health_state
            (service_id,client_id,product_id,domain,profile,stable_state,observed_state,consecutive_count,
             checks_json,first_failure_at,confirmed_failure_at,last_checked_at,updated_at,pending_notification)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			site.ServiceID, site.ClientID, site.ProductID, site.Domain, site.Profile, state.Stable, state.Observed,
			state.Consecutive, string(data), state.FirstFailureAt, state.ConfirmedFailureAt,
			result.CheckedAt, result.CheckedAt, nullableString(state.PendingNotification))
	}
	if err != nil {
		return Transition{}, err
	}
	if err := tx.Commit(); err != nil {
		return Transition{}, err
	}
	return transition, nil
}

func loadState(ctx context.Context, tx *sql.Tx, serviceID int64) (StoredState, bool, error) {
	var state StoredState
	var first, confirmed sql.NullTime
	var pending sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT stable_state,observed_state,consecutive_count,
        first_failure_at,confirmed_failure_at,pending_notification
        FROM mod_modd_health_state WHERE service_id=? FOR UPDATE`, serviceID).Scan(
		&state.Stable, &state.Observed, &state.Consecutive, &first, &confirmed, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if first.Valid {
		state.FirstFailureAt = &first.Time
	}
	if confirmed.Valid {
		state.ConfirmedFailureAt = &confirmed.Time
	}
	if pending.Valid {
		state.PendingNotification = pending.String
	}
	return state, true, nil
}

func (s Store) Prune(ctx context.Context, current []Site) error {
	keep := make(map[int64]struct{}, len(current))
	for _, site := range current {
		keep[site.ServiceID] = struct{}{}
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT service_id FROM mod_modd_health_state`)
	if err != nil {
		return err
	}
	var stale []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if _, ok := keep[id]; !ok {
			stale = append(stale, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range stale {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM mod_modd_health_state WHERE service_id=?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) Pending(ctx context.Context) ([]PendingNotification, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT service_id,product_id,domain,profile,pending_notification,checks_json
        FROM mod_modd_health_state WHERE pending_notification IS NOT NULL AND pending_notification <> ''
        ORDER BY updated_at,service_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []PendingNotification
	for rows.Next() {
		var item PendingNotification
		var raw string
		if err := rows.Scan(&item.ServiceID, &item.ProductID, &item.Domain, &item.Profile, &item.Type, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &item.Result); err != nil {
			return nil, fmt.Errorf("decode stored result for service %d: %w", item.ServiceID, err)
		}
		pending = append(pending, item)
	}
	return pending, rows.Err()
}

func (s Store) NotificationSucceeded(ctx context.Context, item PendingNotification, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE mod_modd_health_state
        SET pending_notification=NULL,last_notification_error=NULL,last_notification_at=?,updated_at=?
        WHERE service_id=? AND pending_notification=?`, now, now, item.ServiceID, item.Type)
	return err
}

func (s Store) NotificationFailed(ctx context.Context, item PendingNotification, message string, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE mod_modd_health_state
        SET last_notification_error=?,updated_at=? WHERE service_id=? AND pending_notification=?`,
		message, now, item.ServiceID, item.Type)
	return err
}

func (s Store) Counts(ctx context.Context) (pending, confirmed int, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT
        COALESCE(SUM(CASE WHEN stable_state <> 'failed' AND observed_state='failed' THEN 1 ELSE 0 END),0),
        COALESCE(SUM(CASE WHEN stable_state='failed' THEN 1 ELSE 0 END),0)
        FROM mod_modd_health_state`).Scan(&pending, &confirmed)
	return
}

func FailureMessages(result SiteResult) []string {
	var messages []string
	for _, check := range result.Checks {
		if !check.Healthy && check.Message != "" {
			messages = append(messages, check.Message)
		}
	}
	return uniqueSorted(messages)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func sortedSiteIDs(sites []Site) []int64 {
	ids := make([]int64, 0, len(sites))
	for _, site := range sites {
		ids = append(ids, site.ServiceID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
