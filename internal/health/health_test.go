package health

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateAndDecodeJob(t *testing.T) {
	job := validJob()
	data := `{"schema":1,"run_id":"run","schedule_window_seconds":0,"site_timeout_seconds":60,` +
		`"database":{"network":"tcp","host":"localhost","port":3306,"socket":"","name":"whmcs","username":"user","password":"secret","tls":"disabled"},` +
		`"webhook_url":"https://chat.googleapis.com/x","configuration":` + configJSON() + `,` +
		`"sites":[{"service_id":1,"client_id":2,"product_id":3,"domain":"example.com","profile":"legacy"}]}`
	if _, err := DecodeJob(bytes.NewBufferString(data)); err != nil {
		t.Fatal(err)
	}
	job.Sites = append(job.Sites, job.Sites[0])
	if err := ValidateJob(job); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestStateTransitions(t *testing.T) {
	now := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	first := ApplyObservation(StoredState{}, false, now)
	if first.State.Stable != "unknown" || first.State.Consecutive != 1 || first.Changed {
		t.Fatalf("unexpected first failure: %+v", first)
	}
	second := ApplyObservation(first.State, false, now.Add(time.Minute))
	if second.State.Stable != "failed" || second.Notification != "failure" || !second.Changed {
		t.Fatalf("failure was not confirmed: %+v", second)
	}
	recoveryPending := ApplyObservation(second.State, true, now.Add(2*time.Minute))
	if recoveryPending.State.Stable != "failed" || recoveryPending.State.Consecutive != 1 {
		t.Fatalf("recovery confirmed too early: %+v", recoveryPending)
	}
	recovered := ApplyObservation(recoveryPending.State, true, now.Add(3*time.Minute))
	if recovered.State.Stable != "healthy" || recovered.Notification != "recovery" || !recovered.Changed {
		t.Fatalf("recovery not confirmed: %+v", recovered)
	}
	pendingCleared := ApplyObservation(first.State, true, now.Add(time.Minute))
	if pendingCleared.State.Stable != "healthy" || pendingCleared.Notification != "" {
		t.Fatalf("unconfirmed failure did not clear silently: %+v", pendingCleared)
	}
	failedAfterRecovery := ApplyObservation(recovered.State, false, now.Add(4*time.Minute))
	if failedAfterRecovery.State.PendingNotification != "" {
		t.Fatalf("stale recovery notification retained after failure: %+v", failedAfterRecovery)
	}
}

func TestHTTPDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/healthy", http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	check := checkHTTP(context.Background(), client, server.URL)
	if check.Healthy || !strings.Contains(check.Message, "HTTP 302") {
		t.Fatalf("redirect should fail: %+v", check)
	}
}

func TestAuthorityRequiresOneCompleteServer(t *testing.T) {
	config := validJob().Configuration
	site := Site{Profile: "container"}
	first := map[string][]string{
		"a":         {"192.0.2.10"},
		"edm:mx":    {"mx.example"},
		"edm:spf":   {"v=spf1 -all"},
		"notify:mx": {"mx.example"},
	}
	second := map[string][]string{
		"a":          {"192.0.2.10"},
		"notify:spf": {"v=spf1 -all"},
	}
	if len(validateAuthority(site, config, first)) == 0 || len(validateAuthority(site, config, second)) == 0 {
		t.Fatal("partial answers must not be combined into a passing authority")
	}
	first["notify:spf"] = []string{"v=spf1 -all"}
	if errors := validateAuthority(site, config, first); len(errors) != 0 {
		t.Fatalf("complete authority should pass: %v", errors)
	}
}

func TestOffsetIsStableAndInsideWindow(t *testing.T) {
	first := Offset(42, 300)
	if first != Offset(42, 300) || first < 0 || first >= 300*time.Second {
		t.Fatalf("invalid offset %v", first)
	}
}

func TestNotifierRetriesRetryableResponses(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	now := time.Now()
	notifier := NewNotifier(server.URL)
	notifier.now = func() time.Time { return now }
	notifier.sleep = func(_ context.Context, duration time.Duration) error { now = now.Add(duration); return nil }
	if err := notifier.Send(context.Background(), PendingNotification{Type: "recovery", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func validJob() Job {
	return Job{
		Schema: 1, RunID: "run", SiteTimeoutSeconds: 60,
		Database:   DatabaseConfig{Network: "tcp", Host: "localhost", Port: 3306, Name: "whmcs", Username: "user", TLS: "disabled"},
		WebhookURL: "https://chat.googleapis.com/x",
		Configuration: Configuration{
			HostingIPv4: []string{"192.0.2.10"},
			Email:       EmailConfig{MXPattern: `^mx\\.example$`, SPFPattern: `^v=spf1`, DKIMSelectors: []string{"default"}, DKIMCNAMEPattern: `^dkim\\.example$`},
			Legacy:      HTTPConfig{URLTemplate: "https://{domain}/~/health/check"}, Container: HTTPConfig{URLTemplate: "https://{domain}/~/health/check"},
		},
		Sites: []Site{{ServiceID: 1, ClientID: 2, ProductID: 3, Domain: "example.com", Profile: "legacy"}},
	}
}

func configJSON() string {
	return `{"hosting_ipv4":["192.0.2.10"],"email":{"mx_pattern":"^mx\\\\.example$","spf_pattern":"^v=spf1","dkim_selectors":["default"],"dkim_cname_pattern":"^dkim\\\\.example$"},"legacy":{"url_template":"https://{domain}/~/health/check"},"container":{"url_template":"https://{domain}/~/health/check"}}`
}
