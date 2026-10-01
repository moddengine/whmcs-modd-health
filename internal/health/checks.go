package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type DNSChecker struct {
	System *net.Resolver
	Port   string
}

func (d DNSChecker) Check(ctx context.Context, site Site, config Configuration) DNSReport {
	resolver := d.System
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	port := d.Port
	if port == "" {
		port = "53"
	}
	nsRecords, err := resolver.LookupNS(ctx, site.Domain)
	if err != nil || len(nsRecords) == 0 {
		message := "no delegated nameservers returned"
		if err != nil {
			message = "delegated nameserver lookup failed: " + err.Error()
		}
		return DNSReport{Checks: []Check{{Name: "delegated_nameservers", Message: message}}}
	}
	nameservers := make([]string, 0, len(nsRecords))
	for _, record := range nsRecords {
		nameservers = append(nameservers, normalizeName(record.Host))
	}
	nameservers = uniqueSorted(nameservers)

	type endpoint struct{ name, address string }
	var endpoints []endpoint
	var resolutionErrors []string
	for _, name := range nameservers {
		addresses, lookupErr := resolver.LookupNetIP(ctx, "ip", name)
		if lookupErr != nil {
			resolutionErrors = append(resolutionErrors, fmt.Sprintf("%s address lookup failed: %v", name, lookupErr))
			continue
		}
		for _, address := range addresses {
			endpoints = append(endpoints, endpoint{name, address.String()})
		}
	}
	if len(endpoints) == 0 {
		return DNSReport{
			Nameservers: nameservers,
			Checks: []Check{
				{Name: "delegated_nameservers", Healthy: true, Values: nameservers},
				{Name: "authoritative_dns", Message: strings.Join(resolutionErrors, "; ")},
			},
		}
	}

	observations := make([]AuthorityObservation, len(endpoints))
	var wg sync.WaitGroup
	for i, ep := range endpoints {
		wg.Add(1)
		go func(index int, endpoint endpoint) {
			defer wg.Done()
			dialer := &net.Dialer{}
			authority := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(endpoint.address, port))
			}}
			observations[index] = queryAuthority(ctx, authority, endpoint.name, endpoint.address, site, config)
		}(i, ep)
	}
	wg.Wait()
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Nameserver == observations[j].Nameserver {
			return observations[i].Address < observations[j].Address
		}
		return observations[i].Nameserver < observations[j].Nameserver
	})
	healthy := false
	var failures []string
	for _, observation := range observations {
		if observation.Healthy {
			healthy = true
		} else {
			failures = append(failures, observation.Errors...)
		}
	}
	failures = append(failures, resolutionErrors...)
	check := Check{Name: "authoritative_dns", Healthy: healthy}
	if !healthy {
		check.Message = strings.Join(uniqueSorted(failures), "; ")
	}
	return DNSReport{
		Healthy:     healthy,
		Nameservers: nameservers,
		Authorities: observations,
		Checks: []Check{
			{Name: "delegated_nameservers", Healthy: true, Values: nameservers},
			check,
		},
	}
}

type dnsTask struct {
	key string
	run func() ([]string, error)
}

func queryAuthority(ctx context.Context, resolver *net.Resolver, nameserver, address string, site Site, config Configuration) AuthorityObservation {
	records := make(map[string][]string)
	var tasks []dnsTask
	switch site.Profile {
	case "email":
		tasks = append(tasks,
			dnsTask{"mx", func() ([]string, error) { return lookupMX(ctx, resolver, site.Domain) }},
			dnsTask{"spf", func() ([]string, error) { return lookupSPF(ctx, resolver, site.Domain) }},
		)
		for _, selector := range config.Email.DKIMSelectors {
			name := selector + "._domainkey." + site.Domain
			tasks = append(tasks, dnsTask{"dkim:" + selector, func() ([]string, error) { return lookupCNAME(ctx, resolver, name) }})
		}
	case "legacy":
		tasks = append(tasks, dnsTask{"a", func() ([]string, error) { return lookupA(ctx, resolver, site.Domain) }})
	case "container":
		tasks = append(tasks, dnsTask{"a", func() ([]string, error) { return lookupA(ctx, resolver, site.Domain) }})
		for _, prefix := range []string{"edm", "notify"} {
			name := prefix + "." + site.Domain
			tasks = append(tasks,
				dnsTask{prefix + ":mx", func() ([]string, error) { return lookupMX(ctx, resolver, name) }},
				dnsTask{prefix + ":spf", func() ([]string, error) { return lookupSPF(ctx, resolver, name) }},
			)
		}
	}

	type result struct {
		key    string
		values []string
		err    error
	}
	results := make(chan result, len(tasks))
	for _, task := range tasks {
		go func(task dnsTask) {
			values, err := task.run()
			results <- result{task.key, uniqueSorted(values), err}
		}(task)
	}
	for range tasks {
		item := <-results
		records[item.key] = item.values
		if item.err != nil {
			records[item.key+":error"] = []string{item.err.Error()}
		}
	}

	errs := validateAuthority(site, config, records)
	for key, values := range records {
		if strings.HasSuffix(key, ":error") && len(values) > 0 {
			errs = append(errs, fmt.Sprintf("%s via %s: %s", strings.TrimSuffix(key, ":error"), nameserver, values[0]))
			delete(records, key)
		}
	}
	return AuthorityObservation{
		Nameserver: nameserver,
		Address:    address,
		Healthy:    len(errs) == 0,
		Records:    records,
		Errors:     uniqueSorted(errs),
	}
}

func validateAuthority(site Site, config Configuration, records map[string][]string) []string {
	var errs []string
	switch site.Profile {
	case "email":
		mx := records["mx"]
		mxPattern := regexp.MustCompile(strings.ReplaceAll(config.Email.MXPattern, "{domain}", regexp.QuoteMeta(site.Domain)))
		if len(mx) == 0 {
			errs = append(errs, "missing MX record")
		} else {
			for _, target := range mx {
				if !mxPattern.MatchString(target) {
					errs = append(errs, "MX record did not match expected pattern: "+target)
				}
			}
		}
		spf := records["spf"]
		if len(spf) != 1 {
			errs = append(errs, "expected exactly one SPF record")
		} else if !regexp.MustCompile(config.Email.SPFPattern).MatchString(spf[0]) {
			errs = append(errs, "SPF record did not match expected pattern")
		}
		dkimPattern := regexp.MustCompile(config.Email.DKIMCNAMEPattern)
		for _, selector := range config.Email.DKIMSelectors {
			values := records["dkim:"+selector]
			if len(values) != 1 {
				errs = append(errs, "missing DKIM CNAME for "+selector)
			} else if !dkimPattern.MatchString(values[0]) {
				errs = append(errs, "DKIM CNAME did not match expected pattern for "+selector)
			}
		}
	case "legacy", "container":
		addresses := records["a"]
		allowed := make(map[string]struct{}, len(config.HostingIPv4))
		for _, value := range config.HostingIPv4 {
			allowed[value] = struct{}{}
		}
		if len(addresses) == 0 {
			errs = append(errs, "missing A record")
		}
		for _, address := range addresses {
			if _, ok := allowed[address]; !ok {
				errs = append(errs, "incorrect IP in A record: "+address)
			}
		}
		if site.Profile == "container" {
			for _, prefix := range []string{"edm", "notify"} {
				if len(records[prefix+":mx"]) == 0 {
					errs = append(errs, "missing MX record for "+prefix)
				}
				if len(records[prefix+":spf"]) == 0 {
					errs = append(errs, "missing SPF record for "+prefix)
				}
			}
		}
	}
	return errs
}

func CheckSite(ctx context.Context, dns DNSChecker, client *http.Client, site Site, config Configuration) SiteResult {
	result := SiteResult{ServiceID: site.ServiceID, CheckedAt: time.Now().UTC()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.DNS = dns.Check(ctx, site, config)
	}()
	if site.Profile != "email" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			template := config.Legacy.URLTemplate
			if site.Profile == "container" {
				template = config.Container.URLTemplate
			}
			result.Checks = append(result.Checks, checkHTTP(ctx, client, strings.Replace(template, "{domain}", site.Domain, 1)))
		}()
	}
	wg.Wait()
	result.Checks = append(result.DNS.Checks, result.Checks...)
	result.Healthy = true
	for _, check := range result.Checks {
		result.Healthy = result.Healthy && check.Healthy
	}
	return result
}

func HTTPClient() *http.Client {
	return &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func checkHTTP(ctx context.Context, client *http.Client, target string) Check {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Check{Name: "http", Message: "health check URL invalid"}
	}
	response, err := client.Do(request)
	if err != nil {
		return Check{Name: "http", Message: "health check URL failed: " + err.Error(), Values: []string{target}}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Check{Name: "http", Message: fmt.Sprintf("health check URL failed: HTTP %d", response.StatusCode), Values: []string{target}}
	}
	return Check{Name: "http", Healthy: true, Values: []string{target}}
}

func lookupA(ctx context.Context, resolver *net.Resolver, name string) ([]string, error) {
	addresses, err := resolver.LookupNetIP(ctx, "ip4", name)
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return values, err
}

func lookupMX(ctx context.Context, resolver *net.Resolver, name string) ([]string, error) {
	records, err := resolver.LookupMX(ctx, name)
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, normalizeName(record.Host))
	}
	return values, err
}

func lookupSPF(ctx context.Context, resolver *net.Resolver, name string) ([]string, error) {
	records, err := resolver.LookupTXT(ctx, name)
	var values []string
	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			values = append(values, record)
		}
	}
	return values, err
}

func lookupCNAME(ctx context.Context, resolver *net.Resolver, name string) ([]string, error) {
	target, err := resolver.LookupCNAME(ctx, name)
	if err != nil {
		return nil, err
	}
	target = normalizeName(target)
	if target == normalizeName(name) {
		return nil, errors.New("record is not a CNAME")
	}
	return []string{target}, nil
}

func normalizeName(value string) string { return strings.TrimSuffix(strings.ToLower(value), ".") }

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
