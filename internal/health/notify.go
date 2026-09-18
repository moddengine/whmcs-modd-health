package health

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Notifier struct {
	URL    string
	Client *http.Client
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	last   time.Time
}

func NewNotifier(url string) *Notifier {
	return &Notifier{
		URL:    url,
		Client: &http.Client{Timeout: 15 * time.Second},
		now:    time.Now,
		sleep: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

func (n *Notifier) Send(ctx context.Context, item PendingNotification) error {
	message := notificationText(item)
	body, _ := json.Marshal(map[string]string{"text": message})
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := n.sleep(ctx, time.Duration(1<<(attempt-1))*time.Second); err != nil {
				return err
			}
		}
		if wait := time.Second - n.now().Sub(n.last); !n.last.IsZero() && wait > 0 {
			if err := n.sleep(ctx, wait); err != nil {
				return err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := n.Client.Do(request)
		n.last = n.now()
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
		if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
			break
		}
	}
	return lastErr
}

func notificationText(item PendingNotification) string {
	if item.Type == "recovery" {
		return fmt.Sprintf("RECOVERED: %s (WHMCS service %d, product %d, profile %s) — all required checks are healthy.",
			item.Domain, item.ServiceID, item.ProductID, item.Profile)
	}
	reasons := FailureMessages(item.Result)
	if len(reasons) == 0 {
		reasons = []string{"required health checks failed"}
	}
	return fmt.Sprintf("FAILED: %s (WHMCS service %d, product %d, profile %s) — %s.",
		item.Domain, item.ServiceID, item.ProductID, item.Profile, strings.Join(reasons, "; "))
}
