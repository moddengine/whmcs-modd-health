package health

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func TestStoreAgainstMariaDB(t *testing.T) {
	dsn := os.Getenv("MODD_HEALTH_TEST_DSN")
	if dsn == "" {
		t.Skip("MODD_HEALTH_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE IF EXISTS mod_modd_health_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE mod_modd_health_state (
        service_id BIGINT UNSIGNED PRIMARY KEY, client_id BIGINT UNSIGNED NOT NULL,
        product_id BIGINT UNSIGNED NOT NULL, domain VARCHAR(253) NOT NULL, profile VARCHAR(32) NOT NULL,
        stable_state VARCHAR(16) NOT NULL, observed_state VARCHAR(16) NOT NULL,
        consecutive_count INT UNSIGNED NOT NULL, checks_json MEDIUMTEXT NOT NULL,
        first_failure_at DATETIME NULL, confirmed_failure_at DATETIME NULL,
        last_checked_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
        pending_notification VARCHAR(16) NULL, last_notification_error TEXT NULL,
        last_notification_at DATETIME NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TABLE IF EXISTS mod_modd_health_state`) })

	store := Store{DB: db}
	site := Site{ServiceID: 10, ClientID: 20, ProductID: 30, Domain: "example.com", Profile: "legacy"}
	checkedAt := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	result := SiteResult{ServiceID: site.ServiceID, Healthy: false, CheckedAt: checkedAt, Checks: []Check{{Name: "a", Message: "incorrect IP in A record"}}}
	first, err := store.Save(context.Background(), site, result)
	if err != nil {
		t.Fatal(err)
	}
	if first.State.Stable != "unknown" {
		t.Fatalf("unexpected first state: %+v", first)
	}
	result.CheckedAt = checkedAt.Add(time.Minute)
	second, err := store.Save(context.Background(), site, result)
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Stable != "failed" || second.Notification != "failure" {
		t.Fatalf("failure not confirmed: %+v", second)
	}
	pending, err := store.Pending(context.Background())
	if err != nil || len(pending) != 1 || pending[0].Type != "failure" {
		t.Fatalf("pending notification mismatch: %+v, %v", pending, err)
	}
	if err := store.Prune(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM mod_modd_health_state`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale row not pruned: count=%d err=%v", count, err)
	}
}
