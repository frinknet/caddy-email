package mta

import (
	"bytes"
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

// dkimSignedHeaders is the h= tag: the header fields covered by the signature,
// in the order they are presented to the signing algorithm.
const dkimSignedHeaders = "From:To:Subject:Date:MIME-Version:Content-Type"

// dkimSign prepends a DKIM-Signature header to the message.
// It uses "simple/simple" canonicalization and rsa-sha256.
//
// Per RFC 6376 section 3.7 the signature covers the signed headers (in the
// order given by h=, each terminated with CRLF), followed by the DKIM-Signature
// header itself with an empty b= value and no trailing CRLF. The emitted header
// then carries the base64 signature after "b=".
func dkimSign(raw []byte, cfg *DKIMConfig, fromDomain string) ([]byte, error) {
	if cfg == nil || cfg.parsedKey == nil {
		return raw, nil
	}

	domain := cfg.Domain
	if domain == "" {
		domain = fromDomain
	}
	if domain == "" {
		return raw, nil
	}

	header, body := splitMessage(raw)

	// Body hash: simple canonicalization over the body only.
	sum := sha256.Sum256(canonicalizeSimpleBody(body))
	bh := base64.StdEncoding.EncodeToString(sum[:])

	// The DKIM-Signature header with an empty b= value. This exact byte string
	// is what a verifier reconstructs and hashes.
	unsigned := "DKIM-Signature: " + strings.Join([]string{
		"v=1",
		"a=rsa-sha256",
		"c=simple/simple",
		"d=" + domain,
		"s=" + cfg.Selector,
		"bh=" + bh,
		"h=" + dkimSignedHeaders,
	}, "; ") + "; b="

	// Hash step 2: the signed headers first, in h= order, then the empty-b=
	// DKIM-Signature header, with no trailing CRLF.
	var sigInput []byte
	for _, name := range strings.Split(dkimSignedHeaders, ":") {
		if line, ok := lastHeader(header, name); ok {
			sigInput = append(sigInput, line...)
			sigInput = append(sigInput, '\r', '\n')
		}
	}
	sigInput = append(sigInput, unsigned...)

	digest := sha256.Sum256(sigInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, cfg.parsedKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("dkim sign: %w", err)
	}

	sigHeader := unsigned + base64.StdEncoding.EncodeToString(sig)

	result := make([]byte, 0, len(sigHeader)+2+len(raw))
	result = append(result, sigHeader...)
	result = append(result, '\r', '\n')
	result = append(result, raw...)
	return result, nil
}

// splitMessage splits a raw message into its header block and body at the first
// empty line. When there is no separator the whole input is treated as headers.
func splitMessage(raw []byte) (header, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, nil
}

// canonicalizeSimpleBody applies RFC 6376 section 3.4.3: trailing empty lines
// collapse to a single CRLF, and a missing or empty body canonicalizes to a
// single CRLF.
func canonicalizeSimpleBody(body []byte) []byte {
	core := bytes.TrimRight(body, "\r\n")
	out := make([]byte, 0, len(core)+2)
	out = append(out, core...)
	out = append(out, '\r', '\n')
	return out
}

// lastHeader returns the last line of the header block whose field name matches
// name (case-insensitively), as it appears in the message, without its CRLF.
// RFC 6376 section 5.4.2 requires the physically last instance.
func lastHeader(header []byte, name string) ([]byte, bool) {
	var found []byte
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.EqualFold(string(line[:colon]), name) {
			found = line
		}
	}
	return found, found != nil
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
