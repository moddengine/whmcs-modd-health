package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	spfModifier   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]*=`)
	spfMacro      = regexp.MustCompile(`(?i)^[slodiphv][0-9]*r?[.\-+,/_=]*$`)
	spfTopLabel   = regexp.MustCompile(`(?i)^(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])$`)
	spfDualCIDR   = regexp.MustCompile(`^(?:/([0-9]+))?(?://([0-9]+))?$`)
	dmarcTag      = regexp.MustCompile(`^[a-zA-Z]+$`)
	reportSize    = regexp.MustCompile(`(?i)^[0-9]+[kmgt]?$`)
	uriCharacters = regexp.MustCompile(`^(?:[a-zA-Z0-9:/?#@!$&'()*+,;=._~\[\]-]|%[0-9a-fA-F]{2})+$`)
)

func validateSPF(records []string) error {
	if len(records) != 1 {
		return errors.New("expected exactly one SPF record")
	}
	record := records[0]
	for _, c := range record {
		if c < 32 || c > 126 {
			return errors.New("invalid SPF character")
		}
	}
	terms := strings.Split(record, " ")
	if !strings.EqualFold(terms[0], "v=spf1") {
		return errors.New("invalid SPF version")
	}
	seen := map[string]bool{}
	for _, term := range terms[1:] {
		if term == "" {
			continue
		}
		original := term
		if spfModifier.MatchString(term) {
			name, value, _ := strings.Cut(term, "=")
			name = strings.ToLower(name)
			if name == "redirect" || name == "exp" {
				if seen[name] || !validSPFDomain(value) {
					return fmt.Errorf("invalid SPF %s modifier", name)
				}
				seen[name] = true
			} else if !validSPFMacro(value) {
				return fmt.Errorf("invalid SPF modifier: %s", original)
			}
			continue
		}
		if strings.ContainsRune("+-?~", rune(term[0])) {
			term = term[1:]
		}
		mechanism := strings.ToLower(term)
		if i := strings.IndexAny(mechanism, ":/"); i >= 0 {
			mechanism = mechanism[:i]
		}
		rest := term[len(mechanism):]
		valid := false
		switch mechanism {
		case "all":
			valid = rest == ""
		case "include", "exists":
			valid = strings.HasPrefix(rest, ":") && validSPFDomain(rest[1:])
		case "ptr":
			valid = rest == "" || (strings.HasPrefix(rest, ":") && validSPFDomain(rest[1:]))
		case "a", "mx":
			// Slashes inside macro expansions belong to the macro, not the CIDR suffix.
			i, inMacro := 0, false
			for i < len(rest) {
				if rest[i] == '{' {
					inMacro = true
				}
				if rest[i] == '}' {
					inMacro = false
				}
				if rest[i] == '/' && !inMacro {
					break
				}
				i++
			}
			domain, cidr := rest[:i], rest[i:]
			match := spfDualCIDR.FindStringSubmatch(cidr)
			valid = (domain == "" || (strings.HasPrefix(domain, ":") && validSPFDomain(domain[1:]))) && match != nil
			if valid {
				valid = validCIDR(match[1], 32) && validCIDR(match[2], 128)
			}
		case "ip4", "ip6":
			if strings.HasPrefix(rest, ":") {
				ip, bits, hasBits := strings.Cut(rest[1:], "/")
				address, err := netip.ParseAddr(ip)
				max := 128
				if mechanism == "ip4" {
					max = 32
				}
				valid = err == nil && address.Zone() == "" && ((mechanism == "ip4" && address.Is4()) || (mechanism == "ip6" && address.Is6()))
				if hasBits {
					valid = valid && bits != "" && validCIDR(bits, max)
				}
			}
		}
		if !valid {
			return fmt.Errorf("invalid SPF mechanism: %s", original)
		}
	}
	return nil
}

func validCIDR(value string, max int) bool {
	if value == "" {
		return true
	}
	if len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(value)
	return err == nil && n <= max
}

func validSPFMacro(value string) bool {
	valid, _ := parseSPFMacro(value)
	return valid
}

func parseSPFMacro(value string) (bool, bool) {
	macroEnd := false
	for i := 0; i < len(value); i++ {
		macroEnd = false
		if value[i] < 33 || value[i] > 126 {
			return false, false
		}
		if value[i] != '%' {
			continue
		}
		i++
		if i == len(value) {
			return false, false
		}
		if strings.ContainsRune("%_-", rune(value[i])) {
			macroEnd = true
			continue
		}
		if value[i] != '{' {
			return false, false
		}
		end := strings.IndexByte(value[i:], '}')
		if end < 0 || !spfMacro.MatchString(value[i+1:i+end]) {
			return false, false
		}
		i += end
		macroEnd = true
	}
	return true, macroEnd
}

func validSPFDomain(value string) bool {
	valid, macroEnd := parseSPFMacro(value)
	if value == "" || !valid {
		return false
	}
	if macroEnd {
		return true
	}
	value = strings.TrimSuffix(value, ".")
	i := strings.LastIndexByte(value, '.')
	return i >= 0 && spfTopLabel.MatchString(value[i+1:])
}

func parseDMARC(record string) (map[string]string, error) {
	tags := map[string]string{}
	parts := strings.Split(record, ";")
	for i, part := range parts {
		part = strings.Trim(part, " \t")
		if part == "" && i == len(parts)-1 {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
		if !ok || !dmarcTag.MatchString(name) || value == "" {
			return nil, errors.New("malformed DMARC tag")
		}
		if i == 0 && (name != "v" || value != "DMARC1") {
			return nil, errors.New("invalid DMARC version")
		}
		for _, c := range value {
			if c < 32 || c > 126 {
				return nil, errors.New("invalid DMARC character")
			}
		}
		if _, exists := tags[name]; exists {
			return nil, fmt.Errorf("duplicate DMARC tag: %s", name)
		}
		switch name {
		case "p", "sp", "np", "adkim", "aspf", "psd", "t", "fo":
			value = strings.ToLower(value)
		}
		tags[name] = value
		valid := true
		switch name {
		case "v":
			valid = value == "DMARC1"
		case "p", "sp", "np":
			valid = value == "none" || value == "quarantine" || value == "reject"
		case "adkim", "aspf":
			valid = value == "r" || value == "s"
		case "psd":
			valid = value == "y" || value == "n" || value == "u"
		case "t":
			valid = value == "y" || value == "n"
		case "fo":
			seen := map[string]bool{}
			for _, option := range strings.Split(value, ":") {
				if (option != "0" && option != "1" && option != "d" && option != "s") || seen[option] {
					valid = false
				}
				seen[option] = true
			}
			valid = valid && !(seen["0"] && seen["1"])
		case "rua", "ruf":
			for _, target := range strings.Split(value, ",") {
				target = strings.Trim(target, " \t")
				uri, size, hasSize := strings.Cut(target, "!")
				parsed, err := url.Parse(uri)
				if err != nil || parsed.Scheme == "" || !uriCharacters.MatchString(uri) || (hasSize && !reportSize.MatchString(size)) {
					valid = false
				}
				// Brackets are reserved for IP literals in the URI authority.
				if err == nil {
					remainder := strings.TrimPrefix(uri, parsed.Scheme+":")
					if strings.HasPrefix(remainder, "//") {
						remainder = remainder[2:]
						if i := strings.IndexAny(remainder, "/?#"); i >= 0 {
							remainder = remainder[i:]
						} else {
							remainder = ""
						}
					}
					if strings.ContainsAny(remainder, "[]") {
						valid = false
					}
				}
				if err == nil && parsed.Scheme == "mailto" && (parsed.Opaque == "" || !strings.Contains(parsed.Opaque, "@")) {
					valid = false
				}
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid DMARC %s value", name)
		}
	}
	if tags["v"] != "DMARC1" {
		return nil, errors.New("missing DMARC version")
	}
	// RFC 9989 defaults an omitted policy to monitoring mode.
	if tags["p"] == "" {
		tags["p"] = "none"
	}
	return tags, nil
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func lookupDMARC(ctx context.Context, direct, system *net.Resolver, domain string) ([]string, string, error) {
	return discoverDMARC(ctx, domain, func(ctx context.Context, candidate string) ([]string, error) {
		resolver := system
		if candidate == domain {
			resolver = direct
		}
		return resolver.LookupTXT(ctx, "_dmarc."+candidate)
	})
}

func discoverDMARC(ctx context.Context, domain string, lookup func(context.Context, string) ([]string, error)) ([]string, string, error) {
	var selected []string
	selectedDomain := ""
	for candidate := domain; candidate != ""; {
		if err := ctx.Err(); err != nil {
			return nil, candidate, err
		}
		txt, err := lookup(ctx, candidate)
		if err != nil && !isNotFound(err) {
			return nil, candidate, fmt.Errorf("DMARC lookup for %s: %w", candidate, err)
		}
		var records []string
		for _, record := range txt {
			first, _, _ := strings.Cut(record, ";")
			name, value, _ := strings.Cut(first, "=")
			if strings.Trim(name, " \t") == "v" && strings.Trim(value, " \t") == "DMARC1" {
				records = append(records, record)
			}
		}
		if len(records) > 1 {
			return records, candidate, fmt.Errorf("multiple DMARC records at %s", candidate)
		}
		if len(records) == 1 {
			tags, err := parseDMARC(records[0])
			if err != nil {
				return records, candidate, fmt.Errorf("DMARC at %s: %w", candidate, err)
			}
			if candidate == domain {
				return records, candidate, nil
			}
			if tags["psd"] == "y" {
				// A PSD policy only applies when its immediate child has no policy.
				child := strings.TrimSuffix(domain, "."+candidate)
				if i := strings.LastIndexByte(child, '.'); i >= 0 {
					child = child[i+1:]
				}
				organizational := child + "." + candidate
				if selectedDomain != organizational {
					return records, candidate, nil
				}
				return selected, selectedDomain, nil
			}
			selected, selectedDomain = records, candidate
			if tags["psd"] == "n" {
				return selected, selectedDomain, nil
			}
		}
		labels := strings.Split(candidate, ".")
		if len(labels) == 1 {
			break
		}
		if candidate == domain && len(labels) > 8 {
			labels = labels[len(labels)-8:]
		}
		candidate = strings.Join(labels[1:], ".")
	}
	if selectedDomain != "" {
		return selected, selectedDomain, nil
	}
	return nil, "", errors.New("missing DMARC record (including inherited policy)")
}

func inspectMail(ctx context.Context, direct, system *net.Resolver, site Site, records map[string][]string) ([]Check, string) {
	mx := records["mx"]
	mxCheck := Check{Name: "mx", Healthy: true, Values: mx}
	if len(records["mx:error"]) > 0 {
		mxCheck.Healthy = false
		mxCheck.Message = records["mx:error"][0]
	}
	hasMail := len(mx) > 0 && !(len(mx) == 1 && mx[0] == ".")
	if site.Profile == "email" && !hasMail && len(records["mx:error"]) == 0 {
		mxCheck.Healthy = false
		mxCheck.Message = "missing usable MX record"
	}
	checks := []Check{mxCheck}
	policyDomain := ""
	if (hasMail && mxCheck.Healthy) || site.Profile == "email" {
		var spf, dmarc []string
		var spfErr, dmarcErr error
		done := make(chan struct{})
		go func() { spf, spfErr = lookupSPF(ctx, direct, site.Domain); close(done) }()
		dmarc, policyDomain, dmarcErr = lookupDMARC(ctx, direct, system, site.Domain)
		<-done
		records["spf"], records["dmarc"] = spf, dmarc
		if spfErr == nil || isNotFound(spfErr) {
			spfErr = validateSPF(spf)
		}
		for _, result := range []struct {
			name   string
			values []string
			err    error
		}{{"spf", spf, spfErr}, {"dmarc", dmarc, dmarcErr}} {
			check := Check{Name: result.name, Healthy: result.err == nil, Values: result.values}
			if result.err != nil {
				check.Message = dnsErrorMessage(result.err)
				records[result.name+":error"] = []string{result.err.Error()}
			}
			checks = append(checks, check)
		}
	} else {
		message := "not applicable (no mail service)"
		if !mxCheck.Healthy {
			message = "not checked (MX lookup failed)"
		}
		checks = append(checks, Check{Name: "spf", Healthy: mxCheck.Healthy, Message: message}, Check{Name: "dmarc", Healthy: mxCheck.Healthy, Message: message})
	}
	if site.Profile == "container" {
		for _, prefix := range []string{"edm", "notify"} {
			mx := records[prefix+":mx"]
			mxCheck := Check{Name: prefix + ":mx", Healthy: len(mx) > 0 && !(len(mx) == 1 && mx[0] == "."), Values: mx}
			if !mxCheck.Healthy {
				mxCheck.Message = "missing usable MX record"
			}
			if values := records[prefix+":mx:error"]; len(values) > 0 {
				mxCheck.Healthy = false
				mxCheck.Message = values[0]
			}
			checks = append(checks, mxCheck)
			check := Check{Name: prefix + ":spf", Healthy: true, Values: records[prefix+":spf"]}
			if err := validateSPF(check.Values); err != nil {
				check.Healthy = false
				check.Message = err.Error()
			}
			if values := records[prefix+":spf:error"]; len(values) > 0 {
				check.Healthy = false
				check.Message = values[0]
			}
			checks = append(checks, check)
		}
	}
	return checks, policyDomain
}
