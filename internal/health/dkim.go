package health

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var dkimTagName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// validateDKIMKey checks the DNS key record, not an email signature. LookupTXT
// joins the character strings within each TXT RR before this is called.
func validateDKIMKey(record string) error {
	tags := make(map[string]string)
	parts := strings.Split(strings.TrimSpace(record), ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" && i == len(parts)-1 {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !dkimTagName.MatchString(name) {
			return errors.New("malformed key tag")
		}
		if _, exists := tags[name]; exists {
			return fmt.Errorf("duplicate %s tag", name)
		}
		if name == "v" && (i != 0 || value != "DKIM1") {
			return errors.New("v tag must be DKIM1 and appear first")
		}
		tags[name] = value
	}
	publicKey, ok := tags["p"]
	if !ok {
		return errors.New("missing p public key tag")
	}
	publicKey = strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(publicKey)
	if publicKey == "" {
		return errors.New("public key is revoked (empty p tag)")
	}
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.New("public key is not valid base64")
	}
	keyType, present := tags["k"]
	if !present {
		keyType = "rsa"
	}
	switch keyType {
	case "rsa":
		parsed, err := x509.ParsePKIXPublicKey(key)
		if err != nil {
			return errors.New("invalid RSA public key")
		}
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 1024 {
			return errors.New("expected an RSA public key of at least 1024 bits")
		}
	case "ed25519":
		if len(key) != ed25519.PublicKeySize {
			return errors.New("Ed25519 public key must be 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported key type %q", keyType)
	}
	return nil
}
