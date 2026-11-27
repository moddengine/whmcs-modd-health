package health

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Axigen's published RSA key for the reported regression domain.
const testDKIMKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5tPpHJh0FaYIVJYDKdcdZtsS4DSzaSLBoQw1TjbOCwYgnP7UPHEdKOLsGF6K8ChYK0E/bUUAbe180MKTMQsllVo3cSfIK3UOAdxMX6MgWOHLmEE2dRZT7KZO5ViVfj8DNpxjmaKewbiT50/QnlPuUzbjIoXVwvP1fmpEhOCHpPTf35jFX1drRltm2Xk3ccJphTJSgp5F/HO6QVVdHbsHGF4MR6mmLwupeb5KYEfZziTB1QdtSxg5L8gRkiy0gBmzA1/q/DfuyuCXvQbEi5uOxuuuDTmd2LR52rwTQ+lcf2SOJDyVJXr863JIIc+9sp8vIpdq0Hv9gUILXUWbdMm6eQIDAQAB"
const testDKIMRecord = "v=DKIM1; k=rsa; p=" + testDKIMKey + ";"

func TestValidateDKIMKey(t *testing.T) {
	for _, record := range []string{
		testDKIMRecord,
		"p=" + testDKIMKey, // v and k have defaults in RFC 6376.
		"v=DKIM1; k=rsa; n=Axigen; p=" + testDKIMKey[:200] + "\r\n\t" + testDKIMKey[200:] + "; t=s;",
		"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		if err := validateDKIMKey(record); err != nil {
			t.Errorf("valid key rejected: %v", err)
		}
	}
	for name, record := range map[string]string{
		"CNAME target":      "dkim.example",
		"missing key":       "v=DKIM1; k=rsa;",
		"revoked":           "v=DKIM1; p=;",
		"bad base64":        "v=DKIM1; p=!!!;",
		"bad DER":           "v=DKIM1; p=YWJj;",
		"wrong version":     "v=DKIM2; p=" + testDKIMKey,
		"version order":     "k=rsa; v=DKIM1; p=" + testDKIMKey,
		"duplicate":         testDKIMRecord + "p=" + testDKIMKey,
		"unknown algorithm": "k=other; p=" + testDKIMKey,
		"wrong key type":    "k=ed25519; p=" + testDKIMKey,
		"empty tag":         "v=DKIM1;; p=" + testDKIMKey,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDKIMKey(record); err == nil {
				t.Fatal("invalid key accepted")
			}
		})
	}
}

func TestEmailRequiresTXTKeyForEverySelector(t *testing.T) {
	config := validJob().Configuration
	config.Email.MXPattern = `^mx\.example$`
	config.Email.DKIMSelectors = []string{"axigen", "default"}
	records := map[string][]string{
		"mx": {"mx.example"}, "spf": {"v=spf1 -all"},
		"dkim:axigen": {testDKIMRecord}, "dkim:default": {testDKIMRecord},
	}
	site := Site{Profile: "email"}
	if errs := validateAuthority(site, config, records); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, values := range [][]string{nil, {testDKIMRecord, "p=other"}, {"dkim.example"}, {"v=DKIM1; p="}} {
		records["dkim:axigen"] = values
		if errs := validateAuthority(site, config, records); len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "axigen") {
			t.Fatalf("bad selector must fail: %v", errs)
		}
	}
}

func TestQueryAuthorityReadsSplitDKIMTXT(t *testing.T) {
	const domain = "malcolmhundley.com.au"
	resolver, _ := dnsFixture(t, map[string][]dnsAnswer{
		domain:                        {mx(0, "mx.example"), txt("v=spf1 -all")},
		"_dmarc." + domain:            {txt("v=DMARC1; p=none")},
		"axigen._domainkey." + domain: {txt(testDKIMRecord[:200], testDKIMRecord[200:])},
	}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := validJob().Configuration
	config.Email.MXPattern = `^mx\.example$`
	config.Email.DKIMSelectors = []string{"axigen"}
	result := queryAuthority(ctx, resolver, resolver, "ns.example", "127.0.0.1", Site{Domain: domain, Profile: "email"}, config)
	if !result.Healthy || len(result.Records["dkim:axigen"]) != 1 || result.Records["dkim:axigen"][0] != testDKIMRecord {
		t.Fatalf("split TXT key should pass authoritative checks: %+v", result)
	}
}
