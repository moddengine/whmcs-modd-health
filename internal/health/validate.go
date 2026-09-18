package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func DecodeJob(r io.Reader) (Job, error) {
	var job Job
	dec := json.NewDecoder(io.LimitReader(r, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		return job, fmt.Errorf("decode job: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return job, errors.New("job must contain exactly one JSON document")
	}
	return job, ValidateJob(job)
}

func ValidateJob(job Job) error {
	if job.Schema != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", job.Schema)
	}
	if job.RunID == "" || len(job.RunID) > 128 {
		return errors.New("run_id is required and must not exceed 128 characters")
	}
	if job.ScheduleWindowSeconds < 0 || job.ScheduleWindowSeconds > 300 {
		return errors.New("schedule_window_seconds must be between 0 and 300")
	}
	if job.SiteTimeoutSeconds < 1 || job.SiteTimeoutSeconds > 60 {
		return errors.New("site_timeout_seconds must be between 1 and 60")
	}
	if err := validateDatabase(job.Database); err != nil {
		return err
	}
	if err := ValidateConfiguration(job.Configuration); err != nil {
		return err
	}
	if job.WebhookURL == "" {
		return errors.New("webhook_url is required")
	}
	if err := validateHTTPSURL(job.WebhookURL, false); err != nil {
		return fmt.Errorf("webhook_url: %w", err)
	}
	seen := make(map[int64]struct{}, len(job.Sites))
	for i, site := range job.Sites {
		if site.ServiceID < 1 || site.ClientID < 1 || site.ProductID < 1 {
			return fmt.Errorf("site %d has invalid identifiers", i)
		}
		if _, exists := seen[site.ServiceID]; exists {
			return fmt.Errorf("duplicate service_id %d", site.ServiceID)
		}
		seen[site.ServiceID] = struct{}{}
		if !ValidDomain(site.Domain) {
			return fmt.Errorf("site %d has invalid domain", site.ServiceID)
		}
		if site.Profile != "email" && site.Profile != "legacy" && site.Profile != "container" {
			return fmt.Errorf("site %d has invalid profile", site.ServiceID)
		}
	}
	return nil
}

func ValidateConfiguration(config Configuration) error {
	for _, value := range config.HostingIPv4 {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return fmt.Errorf("invalid hosting IPv4 address %q", value)
		}
	}
	for name, pattern := range map[string]string{
		"email MX":   config.Email.MXPattern,
		"email SPF":  config.Email.SPFPattern,
		"DKIM CNAME": config.Email.DKIMCNAMEPattern,
	} {
		if pattern == "" {
			return fmt.Errorf("%s pattern is required", name)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid %s pattern: %w", name, err)
		}
	}
	if len(config.Email.DKIMSelectors) == 0 {
		return errors.New("at least one DKIM selector is required")
	}
	for _, selector := range config.Email.DKIMSelectors {
		if !domainLabel.MatchString(strings.ToLower(selector)) {
			return fmt.Errorf("invalid DKIM selector %q", selector)
		}
	}
	for name, template := range map[string]string{"legacy": config.Legacy.URLTemplate, "container": config.Container.URLTemplate} {
		if strings.Count(template, "{domain}") != 1 {
			return fmt.Errorf("%s URL template must contain {domain} exactly once", name)
		}
		if strings.Contains(strings.Replace(template, "{domain}", "", 1), "{") {
			return fmt.Errorf("%s URL template contains an unsupported placeholder", name)
		}
		if err := validateHTTPSURL(strings.Replace(template, "{domain}", "example.com", 1), true); err != nil {
			return fmt.Errorf("%s URL template: %w", name, err)
		}
	}
	return nil
}

func validateDatabase(db DatabaseConfig) error {
	if db.Name == "" || db.Username == "" {
		return errors.New("database name and username are required")
	}
	if db.Network == "unix" {
		if db.Socket == "" {
			return errors.New("database socket is required for unix network")
		}
	} else if db.Network == "tcp" {
		if net.ParseIP(db.Host) == nil && !ValidDomain(strings.ToLower(db.Host)) && db.Host != "localhost" {
			return errors.New("database host is invalid")
		}
		if db.Port < 1 || db.Port > 65535 {
			return errors.New("database port is invalid")
		}
	} else {
		return errors.New("database network must be tcp or unix")
	}
	if db.TLS != "disabled" && db.TLS != "preferred" && db.TLS != "required" {
		return errors.New("database TLS must be disabled, preferred, or required")
	}
	return nil
}

func validateHTTPSURL(value string, allowTemplate bool) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("must be an HTTPS URL without credentials or a fragment")
	}
	if !allowTemplate && strings.Contains(value, "{") {
		return errors.New("must not contain template placeholders")
	}
	return nil
}

func ValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || domain != strings.ToLower(domain) || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}
