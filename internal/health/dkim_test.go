package health

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
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
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			query := buffer[:n]
			// Copy the DNS question, without the optional EDNS section.
			end := 12
			for end < n && query[end] != 0 {
				end += int(query[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			name := string(query[12 : end-4])
			qtype := binary.BigEndian.Uint16(query[end-4 : end-2])
			var data []byte
			if qtype == 15 {
				data = []byte{0, 0, 2, 'm', 'x', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
			} else if qtype == 16 {
				text := "v=spf1 -all"
				if strings.Contains(name, "_domainkey") {
					text = testDKIMRecord
				}
				for len(text) > 0 {
					size := min(len(text), 200)
					data = append(data, byte(size))
					data = append(data, text[:size]...)
					text = text[size:]
				}
			}
			response := append([]byte(nil), query[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8580)
			binary.BigEndian.PutUint16(response[6:8], 1)
			binary.BigEndian.PutUint16(response[10:12], 0)
			response = append(response, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60, byte(len(data)>>8), byte(len(data)))
			response = append(response, data...)
			_, _ = server.WriteTo(response, peer)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := validJob().Configuration
	config.Email.MXPattern = `^mx\.example$`
	config.Email.DKIMSelectors = []string{"axigen"}
	result := queryAuthority(ctx, resolver, "ns.example", "127.0.0.1", Site{Domain: "malcolmhundley.com.au", Profile: "email"}, config)
	if !result.Healthy || len(result.Records["dkim:axigen"]) != 1 || result.Records["dkim:axigen"][0] != testDKIMRecord {
		t.Fatalf("split TXT key should pass authoritative checks: %+v", result)
	}
}
