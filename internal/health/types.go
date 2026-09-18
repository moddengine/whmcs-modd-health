package health

import "time"

const SchemaVersion = 1

var Version = "dev"

type Job struct {
	Schema                int            `json:"schema"`
	RunID                 string         `json:"run_id"`
	ScheduleWindowSeconds int            `json:"schedule_window_seconds"`
	SiteTimeoutSeconds    int            `json:"site_timeout_seconds"`
	Database              DatabaseConfig `json:"database"`
	WebhookURL            string         `json:"webhook_url"`
	Configuration         Configuration  `json:"configuration"`
	Sites                 []Site         `json:"sites"`
}

type DatabaseConfig struct {
	Network  string `json:"network"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Socket   string `json:"socket"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      string `json:"tls"`
}

type Configuration struct {
	HostingIPv4 []string    `json:"hosting_ipv4"`
	Email       EmailConfig `json:"email"`
	Legacy      HTTPConfig  `json:"legacy"`
	Container   HTTPConfig  `json:"container"`
}

type EmailConfig struct {
	MXPattern        string   `json:"mx_pattern"`
	SPFPattern       string   `json:"spf_pattern"`
	DKIMSelectors    []string `json:"dkim_selectors"`
	DKIMCNAMEPattern string   `json:"dkim_cname_pattern"`
}

type HTTPConfig struct {
	URLTemplate string `json:"url_template"`
}

type Site struct {
	ServiceID int64  `json:"service_id"`
	ClientID  int64  `json:"client_id"`
	ProductID int64  `json:"product_id"`
	Domain    string `json:"domain"`
	Profile   string `json:"profile"`
}

type Check struct {
	Name    string   `json:"name"`
	Healthy bool     `json:"healthy"`
	Message string   `json:"message,omitempty"`
	Values  []string `json:"values,omitempty"`
}

type AuthorityObservation struct {
	Nameserver string              `json:"nameserver"`
	Address    string              `json:"address"`
	Healthy    bool                `json:"healthy"`
	Records    map[string][]string `json:"records,omitempty"`
	Errors     []string            `json:"errors,omitempty"`
}

type DNSReport struct {
	Healthy     bool                   `json:"healthy"`
	Nameservers []string               `json:"nameservers"`
	Authorities []AuthorityObservation `json:"authorities"`
	Checks      []Check                `json:"checks"`
}

type SiteResult struct {
	ServiceID int64     `json:"service_id"`
	Healthy   bool      `json:"healthy"`
	DNS       DNSReport `json:"dns"`
	Checks    []Check   `json:"checks"`
	CheckedAt time.Time `json:"checked_at"`
}

type Summary struct {
	RunID                string `json:"run_id"`
	Discovered           int    `json:"discovered"`
	Checked              int    `json:"checked"`
	PendingFailures      int    `json:"pending_failures"`
	ConfirmedFailures    int    `json:"confirmed_failures"`
	Transitions          int    `json:"state_transitions"`
	NotificationFailures int    `json:"notification_failures"`
	ElapsedMilliseconds  int64  `json:"elapsed_ms"`
	Error                string `json:"error,omitempty"`
}

type StoredState struct {
	Stable              string
	Observed            string
	Consecutive         int
	FirstFailureAt      *time.Time
	ConfirmedFailureAt  *time.Time
	PendingNotification string
}

type Transition struct {
	State        StoredState
	Notification string
	Changed      bool
}
