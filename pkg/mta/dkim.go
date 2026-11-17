package mta

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// DKIMConfig holds DKIM signing parameters for outbound messages.
type DKIMConfig struct {
	Selector   string `json:"selector,omitempty"`
	Domain     string `json:"domain,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`

	parsedKey *rsa.PrivateKey
}

// dkimSign adds a DKIM-Signature header to the message body.
// It uses "simple/simple" canonicalization and sha256.
func dkimSign(body []byte, cfg *DKIMConfig, fromDomain string) ([]byte, error) {
	if cfg == nil || cfg.parsedKey == nil {
		return body, nil
	}

	domain := cfg.Domain
	if domain == "" {
		domain = fromDomain
	}
	if domain == "" {
		return body, nil
	}

	// Compute body hash (simple canonicalization — no transformation)
	hasher := sha256.New()
	hasher.Write(body)
	bh := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	// Build the unsigned DKIM-Signature header
	sigHeaders := []string{
		"v=1",
		"a=rsa-sha256",
		"c=simple/simple",
		fmt.Sprintf("d=%s", domain),
		fmt.Sprintf("s=%s", cfg.Selector),
		"bh=" + bh,
		"h=From:To:Subject:Date:MIME-Version:Content-Type",
	}
	sigHeader := "DKIM-Signature: " + strings.Join(sigHeaders, "; ") + ";"

	// Compute the signature over the header (simple canonicalization)
	sigInput := sigHeader + "\r\n"
	// Add the listed headers from the body (simple: header line + CRLF)
	headers := extractDKIMHeaders(body, strings.Split("From:To:Subject:Date:MIME-Version:Content-Type", ":"))
	for _, h := range headers {
		sigInput += h + "\r\n"
	}

	hasher = sha256.New()
	hasher.Write([]byte(sigInput))
	digest := hasher.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, cfg.parsedKey, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("dkim sign: %w", err)
	}

	// Append the signature value
	sigHeader += " b=" + base64.StdEncoding.EncodeToString(sig)

	// Prepend the DKIM-Signature header to the body
	result := make([]byte, 0, len(sigHeader)+2+len(body))
	result = append(result, []byte(sigHeader+"\r\n")...)
	result = append(result, body...)
	return result, nil
}

// extractDKIMHeaders extracts header lines matching the given names from the raw message.
// Simple canonicalization: return header name + ":" + value (unfolded, no whitespace changes).
func extractDKIMHeaders(raw []byte, names []string) []string {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	var result []string
	for _, line := range strings.Split(string(raw), "\r\n") {
		if line == "" {
			break
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		if want[name] {
			result = append(result, line)
			delete(want, name) // first occurrence only
		}
	}
	return result
}

// parseDKIMKey decodes a PEM-encoded RSA private key.
func parseDKIMKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("dkim: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dkim: parse private key: %w", err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dkim: not an RSA private key")
	}
	return rsaKey, nil
}
