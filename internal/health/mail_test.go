package health

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSPFSyntax(t *testing.T) {
	valid := []string{"v=spf1", "v=spf1 -all", "V=SPF1 A MX ~ALL", "v=spf1 ip4:0.0.0.0/0 ip6:2001:db8::/32 ?all", "v=spf1 a/24//64 mx:mail.example.com//128 ptr include:_spf.example.com exists:%{ir}.%{v}._spf.%{d2} redirect=example.com exp=why.example.com", "v=spf1 x-foo=%{d} x-foo= -all", "v=spf1 a:%{d/}.example.com/32"}
	invalid := []string{"v=spf10 -all", "v=spf1\t-all", "v=spf1 +", "v=spf1 all:example.com", "v=spf1 include:", "v=spf1 include:example.123", "v=spf1 a/33", "v=spf1 a//129", "v=spf1 a/01", "v=spf1 ip4:300.1.1.1", "v=spf1 ip4:192.0.2.1/33", "v=spf1 ip6:192.0.2.1", "v=spf1 ip6:fe80::1%eth0", "v=spf1 redirect=example.com redirect=other.com", "v=spf1 include:%{z}.example.com", "v=spf1 exists:%{c}", "v=spf1 exists:%{d", "v=spf1 exists:foo}", "v=spf1 include:%%{d}", "v=spf1 mystery", "v=spf1 -redirect=example.com"}
	for _, record := range valid {
		t.Run(record, func(t *testing.T) {
			if err := validateSPF([]string{record}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, record := range invalid {
		t.Run(record, func(t *testing.T) {
			if err := validateSPF([]string{record}); err == nil {
				t.Fatal("accepted malformed SPF")
			}
		})
	}
	for _, records := range [][]string{nil, {"v=spf1 -all", "v=spf1 -all"}} {
		if validateSPF(records) == nil {
			t.Fatal("accepted missing/duplicate SPF")
		}
	}
}

func TestDMARCSyntax(t *testing.T) {
	for _, record := range []string{"v=DMARC1; p=none", "v=DMARC1; p=NONE; aspf=S; adkim=R; psd=N; t=Y; fo=1:D:S", "v=DMARC1", "v = DMARC1; p=reject; sp=quarantine; np=none; psd=n; t=y; aspf=s; adkim=r; fo=1:d:s; rua=mailto:reports@example.com!10m; x=extension;", "v=DMARC1; p=none; rua=https://[2001:db8::1]/report", "v=DMARC1; p=none; rua=mailto:report@example.com%7C", "v=DMARC1; p=none; pct=50; rf=afrf; ri=86400"} {
		if _, err := parseDMARC(record); err != nil {
			t.Fatalf("%s: %v", record, err)
		}
	}
	for _, record := range []string{"v=dmarc1; p=none", "p=none; v=DMARC1", "v=DMARC1; p=bad", "v=DMARC1; p=none; p=reject", "v=DMARC1;;p=none", "v=DMARC1; psd=bad", "v=DMARC1; aspf=bad", "v=DMARC1; fo=0:1", "v=DMARC1; fo=d:d", "v=DMARC1; rua=broken", "v=DMARC1; rua=mailto:report@example.com|", "v=DMARC1; rua=mailto:report@example.com{", "v=DMARC1; rua=mailto:report@example.com%GG", "v=DMARC1; rua=foo:[invalid]", "v=DMARC1; rua=mailto:no-address", "v=DMARC1; t=z", "v=DMARC1; p=none\n"} {
		if _, err := parseDMARC(record); err == nil {
			t.Fatalf("accepted %q", record)
		}
	}
}

func TestDMARCDiscovery(t *testing.T) {
	tests := []struct {
		name, domain string
		records      map[string][]string
		want         string
		fail         bool
	}{
		{"direct", "mail.example.com", map[string][]string{"mail.example.com": {"v=DMARC1; p=none"}}, "mail.example.com", false},
		{"organization", "a.mail.example.com", map[string][]string{"mail.example.com": {"v=DMARC1; p=none"}, "example.com": {"v=DMARC1; p=reject"}}, "example.com", false},
		{"boundary", "a.mail.example.com", map[string][]string{"mail.example.com": {"v=DMARC1; psd=n; p=none"}, "example.com": {"v=DMARC1; p=reject"}}, "mail.example.com", false},
		{"psd", "a.example.co.uk", map[string][]string{"co.uk": {"v=DMARC1; psd=y; p=reject"}}, "co.uk", false},
		{"psd preserves organization", "a.example.co.uk", map[string][]string{"example.co.uk": {"v=DMARC1; p=none"}, "co.uk": {"v=DMARC1; psd=y; p=reject"}}, "example.co.uk", false},
		{"psd skips intermediate", "a.mail.example.co.uk", map[string][]string{"mail.example.co.uk": {"v=DMARC1; p=none"}, "co.uk": {"v=DMARC1; psd=y; p=reject"}}, "co.uk", false},
		{"missing", "example.com", nil, "", true},
		{"unrelated", "example.com", map[string][]string{"example.com": {"verification=ok"}}, "", true},
		{"duplicate", "example.com", map[string][]string{"example.com": {"v=DMARC1", "v=DMARC1"}}, "example.com", true},
		{"malformed direct", "a.example.com", map[string][]string{"a.example.com": {"v=DMARC1; p=bad"}, "example.com": {"v=DMARC1"}}, "a.example.com", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, domain, err := discoverDMARC(context.Background(), test.domain, func(_ context.Context, domain string) ([]string, error) { return test.records[domain], nil })
			if (err != nil) != test.fail || domain != test.want {
				t.Fatalf("domain=%q err=%v", domain, err)
			}
		})
	}
	count := 0
	_, _, _ = discoverDMARC(context.Background(), "a.b.c.d.e.f.g.h.i.j.example.com", func(_ context.Context, domain string) ([]string, error) { count++; return nil, nil })
	if count != 8 {
		t.Fatalf("expected 8 lookups, got %d", count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := discoverDMARC(ctx, "example.com", func(context.Context, string) ([]string, error) { t.Fatal("lookup after cancellation"); return nil, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// The fixture speaks just enough DNS to exercise net.Resolver without public DNS.
type dnsAnswer struct {
	kind uint16
	data []byte
}

func dnsName(name string) []byte {
	var data []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			data = append(data, byte(len(label)))
			data = append(data, label...)
		}
	}
	return append(data, 0)
}
func txt(parts ...string) dnsAnswer {
	var data []byte
	for _, part := range parts {
		data = append(data, byte(len(part)))
		data = append(data, part...)
	}
	return dnsAnswer{16, data}
}
func mx(pref uint16, host string) dnsAnswer {
	return dnsAnswer{15, append(binary.BigEndian.AppendUint16(nil, pref), dnsName(host)...)}
}
func dnsFixture(t *testing.T, records map[string][]dnsAnswer, failName string, referrals ...map[string][]dnsAnswer) (*net.Resolver, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	calls := new(atomic.Int32)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			q := append([]byte(nil), buffer[:n]...)
			if len(q) < 17 {
				continue
			}
			pos := 12
			var labels []string
			for pos < len(q) && q[pos] != 0 {
				size := int(q[pos])
				pos++
				if pos+size >= len(q) {
					break
				}
				labels = append(labels, string(q[pos:pos+size]))
				pos += size
			}
			pos++
			if pos+4 > len(q) {
				continue
			}
			name := strings.Join(labels, ".")
			kind := binary.BigEndian.Uint16(q[pos:])
			end := pos + 4
			calls.Add(1)
			response := append([]byte(nil), q[:end]...)
			response[2] = 0x85
			response[3] = 0x80
			count := uint16(0)
			if name == "timeout.example.com" {
				continue
			}
			if name == failName {
				response[3] = 0x82
			} else {
				for _, answer := range records[name] {
					if answer.kind != kind {
						continue
					}
					count++
					response = append(response, 0xc0, 0x0c)
					response = binary.BigEndian.AppendUint16(response, kind)
					response = append(response, 0, 1, 0, 0, 0, 60)
					response = binary.BigEndian.AppendUint16(response, uint16(len(answer.data)))
					response = append(response, answer.data...)
				}
			}
			binary.BigEndian.PutUint16(response[6:8], count)
			if count == 0 && len(referrals) > 0 {
				for zone, answers := range referrals[0] {
					if name != zone && !strings.HasSuffix(name, "."+zone) {
						continue
					}
					response[2], response[3] = 0x81, 0
					for _, answer := range answers {
						response = append(response, dnsName(zone)...)
						response = binary.BigEndian.AppendUint16(response, answer.kind)
						response = append(response, 0, 1, 0, 0, 0, 60)
						response = binary.BigEndian.AppendUint16(response, uint16(len(answer.data)))
						response = append(response, answer.data...)
					}
					binary.BigEndian.PutUint16(response[8:10], uint16(len(answers)))
					break
				}
			}
			_, _ = conn.WriteTo(response, addr)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	return resolver, calls
}

func TestMailProfilesWithDNS(t *testing.T) {
	config := validJob().Configuration
	config.Email.MXPattern = ".*"
	config.Email.DKIMCNAMEPattern = ".*"
	for _, profile := range []string{"legacy", "container", "email"} {
		for _, mode := range []string{"valid", "no mx", "null mx", "bad null", "mixed null", "dns error", "duplicate spf", "bad dmarc", "bad subdomain spf", "inherited"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				records := map[string][]dnsAnswer{
					"example.com":                    {{1, []byte{192, 0, 2, 10}}, mx(10, "mx.example.com"), txt("v=spf1 ", "-all"), txt("verification=unrelated")},
					"_dmarc.example.com":             {txt("v=DMARC1; ", "p=none")},
					"default._domainkey.example.com": {{5, dnsName("dkim.example.com")}},
					"edm.example.com":                {mx(10, "mx.example.com"), txt("v=spf1 -all")},
					"notify.example.com":             {mx(10, "mx.example.com"), txt("v=spf1 -all")},
				}
				failName := ""
				switch mode {
				case "no mx":
					records["example.com"] = records["example.com"][:1]
				case "null mx":
					records["example.com"] = []dnsAnswer{{1, []byte{192, 0, 2, 10}}, mx(0, ".")}
				case "bad null":
					records["example.com"] = []dnsAnswer{{1, []byte{192, 0, 2, 10}}, mx(10, ".")}
				case "mixed null":
					records["example.com"] = append(records["example.com"], mx(0, "."))
				case "dns error":
					failName = "example.com"
				case "duplicate spf":
					records["example.com"] = append(records["example.com"], txt("v=spf1 -all"))
				case "bad dmarc":
					records["_dmarc.example.com"] = []dnsAnswer{txt("v=DMARC1; p=broken")}
				case "bad subdomain spf":
					records["notify.example.com"] = []dnsAnswer{mx(10, "mx.example.com"), txt("v=spf1 bad")}
				case "inherited":
					delete(records, "_dmarc.example.com")
				}
				direct, _ := dnsFixture(t, records, failName)
				parent, _ := dnsFixture(t, map[string][]dnsAnswer{"_dmarc.com": {txt("v=DMARC1; psd=y; p=none")}}, "")
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				observation := queryAuthority(ctx, direct, parent, "ns.example", "127.0.0.1", Site{Domain: "example.com", Profile: profile}, config)
				want := mode == "valid" || mode == "inherited" || ((mode == "no mx" || mode == "null mx") && profile != "email") || (mode == "bad subdomain spf" && profile != "container")
				if observation.Healthy != want {
					t.Fatalf("healthy=%v errors=%v records=%v", observation.Healthy, observation.Errors, observation.Records)
				}
				if mode == "inherited" && observation.DMARCPolicyDomain != "com" {
					t.Fatalf("wrong inherited policy: %+v", observation)
				}
				if mode == "valid" && len(observation.Records["spf"]) != 1 {
					t.Fatal("split TXT not joined or unrelated TXT counted")
				}
			})
		}
	}
}

func TestMailDNSTimeout(t *testing.T) {
	resolver, _ := dnsFixture(t, nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	observation := queryAuthority(ctx, resolver, resolver, "ns.example", "127.0.0.1", Site{Domain: "example.com", Profile: "legacy"}, validJob().Configuration)
	if observation.Healthy {
		t.Fatal("cancelled DNS must fail")
	}
}

func TestMailDeadline(t *testing.T) {
	resolver, _ := dnsFixture(t, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	observation := queryAuthority(ctx, resolver, resolver, "ns.example", "127.0.0.1", Site{Domain: "timeout.example.com", Profile: "legacy"}, validJob().Configuration)
	if observation.Healthy || ctx.Err() == nil {
		t.Fatalf("deadline not enforced: %+v", observation)
	}
}

func TestDNSCheckerMailReport(t *testing.T) {
	records := map[string][]dnsAnswer{
		"example.com":        {{2, dnsName("ns.example.com")}, {1, []byte{192, 0, 2, 10}}, mx(10, "mx.example.com"), txt("v=spf1 -all")},
		"ns.example.com":     {{1, []byte{127, 0, 0, 1}}},
		"_dmarc.example.com": {txt("v=DMARC1; p=none")},
	}
	resolver, _ := dnsFixture(t, records, "")
	conn, err := resolver.Dial(context.Background(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	report := (DNSChecker{System: resolver, Port: port}).Check(ctx, Site{Domain: "example.com", Profile: "legacy"}, validJob().Configuration)
	if !report.Healthy || len(report.Authorities) != 1 || report.Authorities[0].DMARCPolicyDomain != "example.com" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestDNSCheckerRecursiveFallback(t *testing.T) {
	for _, mode := range []string{"delegated", "different ns", "missing ns", "bad ip", "bad spf", "missing mx", "dns error"} {
		t.Run(mode, func(t *testing.T) {
			// The recursive resolver can reach the child even though NS discovery selects the parent.
			records := map[string][]dnsAnswer{
				"example.com":            {{2, dnsName("parent.example.com")}},
				"parent.example.com":     {{1, []byte{127, 0, 0, 1}}},
				"sig.example.com":        {{1, []byte{192, 0, 2, 10}}},
				"edm.sig.example.com":    {mx(10, "mx.example.com"), txt("v=spf1 -all")},
				"notify.sig.example.com": {mx(10, "mx.example.com"), txt("v=spf1 -all")},
			}
			switch mode {
			case "different ns":
				records["sig.example.com"] = append(records["sig.example.com"], dnsAnswer{2, dnsName("advertised.example.com")})
				records["advertised.example.com"] = []dnsAnswer{{1, []byte{127, 0, 0, 1}}}
			case "missing ns":
				delete(records, "example.com")
			case "bad ip":
				records["sig.example.com"] = []dnsAnswer{{1, []byte{192, 0, 2, 99}}}
			case "bad spf":
				records["edm.sig.example.com"] = []dnsAnswer{mx(10, "mx.example.com"), txt("v=spf1 broken")}
			case "missing mx":
				records["notify.sig.example.com"] = []dnsAnswer{txt("v=spf1 -all")}
			}
			failName := ""
			if mode == "dns error" {
				failName = "sig.example.com"
			}
			system, _ := dnsFixture(t, records, failName)
			parent, _ := dnsFixture(t, nil, "", map[string][]dnsAnswer{
				"sig.example.com": {{2, dnsName("actual.example.com")}},
			})
			conn, err := parent.Dial(context.Background(), "udp", "")
			if err != nil {
				t.Fatal(err)
			}
			_, port, err := net.SplitHostPort(conn.RemoteAddr().String())
			conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			report := (DNSChecker{System: system, Port: port}).Check(ctx, Site{Domain: "sig.example.com", Profile: "container"}, validJob().Configuration)
			want := mode == "delegated" || mode == "different ns" || mode == "missing ns"
			if report.Healthy != want {
				t.Fatalf("healthy=%v, want %v: %+v", report.Healthy, want, report)
			}
			if want {
				for _, check := range report.Checks {
					if !check.Healthy || check.Message != "" {
						t.Fatalf("successful recursion retained a failure: %+v", check)
					}
				}
				for _, observation := range report.Authorities {
					if !observation.Healthy || len(observation.Errors) != 0 {
						t.Fatalf("successful recursion retained authority warnings: %+v", observation)
					}
				}
			}
		})
	}
}

func TestDNSFailureSummary(t *testing.T) {
	for _, mode := range []string{"missing", "lookup failure"} {
		t.Run(mode, func(t *testing.T) {
			records := map[string][]dnsAnswer{
				"example.com":     {{2, dnsName("ns.example.com")}, {1, []byte{192, 0, 2, 10}}},
				"ns.example.com":  {{1, []byte{127, 0, 0, 1}}},
				"edm.example.com": {mx(10, "mx.example.com"), txt("v=spf1 -all")},
			}
			failName := ""
			if mode == "lookup failure" {
				failName = "notify.example.com"
			}
			resolver, _ := dnsFixture(t, records, failName)
			conn, err := resolver.Dial(context.Background(), "udp", "")
			if err != nil {
				t.Fatal(err)
			}
			_, port, err := net.SplitHostPort(conn.RemoteAddr().String())
			conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			// Absolute names keep the host's search suffix from changing SERVFAIL into NODATA.
			report := (DNSChecker{System: resolver, Port: port}).Check(ctx, Site{Domain: "example.com.", Profile: "container"}, validJob().Configuration)
			want := "notify:mx: record not found; notify:spf: record not found"
			if mode == "lookup failure" {
				want = "notify:mx: DNS lookup failed; notify:spf: DNS lookup failed"
			}
			if report.Healthy || report.Checks[1].Message != want {
				t.Fatalf("expected %q, got %+v", want, report)
			}
			if mode == "lookup failure" && !strings.Contains(strings.Join(report.Authorities[0].Errors, "; "), "server misbehaving") {
				t.Fatal("detailed DNS diagnostics were lost")
			}
		})
	}
}
