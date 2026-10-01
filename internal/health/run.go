package health

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Offset(serviceID int64, window int) time.Duration {
	if window <= 0 {
		return 0
	}
	hash := fnv.New32a()
	fmt.Fprint(hash, serviceID)
	return time.Duration(hash.Sum32()%uint32(window)) * time.Second
}

func normalizeSiteDomain(site Site) Site {
	if site.Profile == "email" {
		if at := strings.LastIndexByte(site.Domain, '@'); at >= 0 {
			site.Domain = site.Domain[at+1:]
		}
	}
	return site
}

func Run(ctx context.Context, job Job) (Summary, error) {
	started := time.Now()
	summary := Summary{RunID: job.RunID, Discovered: len(job.Sites)}
	db, err := OpenDatabase(job.Database)
	if err != nil {
		return finishSummary(summary, started, err), err
	}
	defer db.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = db.PingContext(pingCtx)
	cancel()
	if err != nil {
		return finishSummary(summary, started, fmt.Errorf("database connection failed: %w", err)), err
	}
	store := Store{DB: db}
	dns := DNSChecker{}
	client := HTTPClient()
	var checked, transitions atomic.Int64
	errorsCh := make(chan error, len(job.Sites))
	var wg sync.WaitGroup
	for _, site := range job.Sites {
		site = normalizeSiteDomain(site)
		wg.Add(1)
		go func(site Site) {
			defer wg.Done()
			timer := time.NewTimer(Offset(site.ServiceID, job.ScheduleWindowSeconds))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				errorsCh <- ctx.Err()
				return
			case <-timer.C:
			}
			siteCtx, cancel := context.WithTimeout(ctx, time.Duration(job.SiteTimeoutSeconds)*time.Second)
			result := CheckSite(siteCtx, dns, client, site, job.Configuration)
			cancel()
			transition, err := store.Save(ctx, site, result)
			if err != nil {
				errorsCh <- fmt.Errorf("persist service %d: %w", site.ServiceID, err)
				return
			}
			checked.Add(1)
			if transition.Changed {
				transitions.Add(1)
			}
		}(site)
	}
	wg.Wait()
	close(errorsCh)
	summary.Checked = int(checked.Load())
	summary.Transitions = int(transitions.Load())
	for runErr := range errorsCh {
		if runErr != nil {
			return finishSummary(summary, started, runErr), runErr
		}
	}
	if err := store.Prune(ctx, job.Sites); err != nil {
		return finishSummary(summary, started, fmt.Errorf("prune stale services: %w", err)), err
	}
	pending, err := store.Pending(ctx)
	if err != nil {
		return finishSummary(summary, started, fmt.Errorf("load notifications: %w", err)), err
	}
	notifier := NewNotifier(job.WebhookURL)
	for _, item := range pending {
		now := time.Now().UTC()
		if notifyErr := notifier.Send(ctx, item); notifyErr != nil {
			summary.NotificationFailures++
			if err := store.NotificationFailed(ctx, item, notifyErr.Error(), now); err != nil {
				return finishSummary(summary, started, err), err
			}
			continue
		}
		if err := store.NotificationSucceeded(ctx, item, now); err != nil {
			return finishSummary(summary, started, err), err
		}
	}
	summary.PendingFailures, summary.ConfirmedFailures, err = store.Counts(ctx)
	if err != nil {
		return finishSummary(summary, started, err), err
	}
	return finishSummary(summary, started, nil), nil
}

func finishSummary(summary Summary, started time.Time, err error) Summary {
	summary.ElapsedMilliseconds = time.Since(started).Milliseconds()
	if err != nil {
		summary.Error = err.Error()
	}
	return summary
}
