package mta

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func newTestDKIMConfig(t *testing.T) *DKIMConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &DKIMConfig{Selector: "sel", Domain: "example.com", parsedKey: key}
}

const dkimTestMessage = "From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: Hello\r\n" +
	"Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"Hello, world!\r\n"

func TestDKIMSignVerifies(t *testing.T) {
	cfg := newTestDKIMConfig(t)
	signed, err := dkimSign([]byte(dkimTestMessage), cfg, "example.com")
	if err != nil {
		t.Fatalf("dkimSign: %v", err)
	}
	if !bytes.HasPrefix(signed, []byte("DKIM-Signature: ")) {
		t.Fatalf("signed message does not start with DKIM-Signature")
	}
	if err := verifyDKIM(signed, &cfg.parsedKey.PublicKey); err != nil {
		t.Fatalf("produced signature did not verify: %v", err)
	}
}

func TestDKIMSignNoKeyIsNoOp(t *testing.T) {
	got, err := dkimSign([]byte(dkimTestMessage), nil, "example.com")
	if err != nil {
		t.Fatalf("dkimSign: %v", err)
	}
	if !bytes.Equal(got, []byte(dkimTestMessage)) {
		t.Fatal("message changed despite no configured key")
	}
}

func TestDKIMSignNoDomainIsNoOp(t *testing.T) {
	cfg := newTestDKIMConfig(t)
	cfg.Domain = ""
	got, err := dkimSign([]byte(dkimTestMessage), cfg, "")
	if err != nil {
		t.Fatalf("dkimSign: %v", err)
	}
	if !bytes.Equal(got, []byte(dkimTestMessage)) {
		t.Fatal("message changed despite no domain")
	}
}

// TestDKIMBodyHashEmptyBody pins canonicalizeSimpleBody to the SHA-256 value
// RFC 6376 section 3.4.3 publishes for an empty body.
func TestDKIMBodyHashEmptyBody(t *testing.T) {
	sum := sha256.Sum256(canonicalizeSimpleBody(nil))
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=" {
		t.Fatalf("empty-body canonical hash = %q, want the RFC 6376 value", got)
	}
}

// verifyDKIM checks a signed message against pub. It independently follows the
// RFC 6376 verification steps so a mismatch in how dkimSign built the signature
// (for example a missing empty b= tag) surfaces as a failed verification.
func verifyDKIM(msg []byte, pub *rsa.PublicKey) error {
	header, body := splitMessage(msg)

	var sigLine string
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		if len(line) >= len("DKIM-Signature:") &&
			strings.EqualFold(string(line[:len("DKIM-Signature:")]), "DKIM-Signature:") {
			sigLine = string(line)
			break
		}
	}
	if sigLine == "" {
		return errors.New("no DKIM-Signature header")
	}

	tags := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(sigLine, "DKIM-Signature:"), ";") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		tags[key] = strings.TrimSpace(part[eq+1:])
	}

	// Body hash: the "bh=" tag is the hash of the canonicalized body.
	sum := sha256.Sum256(canonicalizeSimpleBody(body))
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != tags["bh"] {
		return fmt.Errorf("body hash mismatch: computed %s, header says %s", got, tags["bh"])
	}

	// Reconstruct the DKIM-Signature header with the b= value emptied.
	bIdx := strings.LastIndex(sigLine, "b=")
	if bIdx < 0 {
		return errors.New("no b= tag in signature")
	}
	unsigned := sigLine[:bIdx+len("b=")]

	// Hash step 2: signed headers in h= order, then the emptied DKIM-Signature
	// header with no trailing CRLF.
	var sigInput []byte
	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if line, ok := lastHeader(header, name); ok {
			sigInput = append(sigInput, line...)
			sigInput = append(sigInput, '\r', '\n')
		}
	}
	sigInput = append(sigInput, unsigned...)

	digest := sha256.Sum256(sigInput)
	sig, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		return fmt.Errorf("decode b=: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("rsa verify: %w", err)
	}
	return nil
}
