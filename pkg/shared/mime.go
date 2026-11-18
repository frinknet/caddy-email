package shared

import (
	"bytes"
	"net/mail"
	"strings"
	"time"
)

// SanitizeHeaderValue neutralizes CR and LF so a value cannot terminate the
// current header line and inject additional headers into an outbound message.
// It is applied by every builder below, so no caller can emit an injected
// header even if it skips validation.
func SanitizeHeaderValue(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, v)
}

// ValidAddress reports whether s is a syntactically valid RFC 5322 address that
// is safe to place in a message header or an SMTP command. Empty strings, CR/LF
// injection attempts, and anything net/mail cannot parse are rejected.
func ValidAddress(s string) bool {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return false
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return false
	}
	return a.Address != "" && strings.Contains(a.Address, "@")
}

// ValidHeaderValue reports whether v is free of CR/LF and can be written into a
// header without risk of injection.
func ValidHeaderValue(v string) bool {
	return !strings.ContainsAny(v, "\r\n\x00")
}

func writeHeader(b *bytes.Buffer, name, value string) {
	b.WriteString(name)
	b.WriteString(": ")
	b.WriteString(SanitizeHeaderValue(value))
	b.WriteString("\r\n")
}

// BuildSimple constructs a minimal RFC 5322 text/plain message.
// TODO: multipart, attachments, HTML.
func BuildSimple(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	writeHeader(&b, "From", from)
	writeHeader(&b, "To", strings.Join(to, ", "))
	if subject != "" {
		writeHeader(&b, "Subject", subject)
	}
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

// BuildMessage constructs a minimal RFC 5322 text/plain message with optional
// Cc and Reply-To headers. Bcc recipients belong in the envelope only and are
// never written into the headers, so callers must not pass them here.
func BuildMessage(from string, to, cc []string, replyTo, subject, body string) []byte {
	var b bytes.Buffer
	writeHeader(&b, "From", from)
	if len(to) > 0 {
		writeHeader(&b, "To", strings.Join(to, ", "))
	}
	if len(cc) > 0 {
		writeHeader(&b, "Cc", strings.Join(cc, ", "))
	}
	if replyTo != "" {
		writeHeader(&b, "Reply-To", replyTo)
	}
	if subject != "" {
		writeHeader(&b, "Subject", subject)
	}
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}
