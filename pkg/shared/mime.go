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
	_, ok := NormalizeAddress(s)
	return ok
}

// NormalizeAddress parses s and returns its bare addr-spec, so a display name
// ("Name <a@b>") cannot reach the SMTP envelope or a DKIM d= tag. The second
// result is false when s is not a valid address.
func NormalizeAddress(s string) (string, bool) {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address == "" || !strings.Contains(a.Address, "@") {
		return "", false
	}
	return a.Address, true
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

// ReceivedHeader formats an RFC 5321 section 4.4 trace header. from is the
// sending host, remoteAddr its network address when known, by the receiving
// host, proto the SMTP variant ("ESMTP", "ESMTPS"), id an optional queue id,
// and forAddr an optional envelope recipient. The result has no trailing CRLF.
func ReceivedHeader(from, remoteAddr, by, proto, id, forAddr string, t time.Time) string {
	var b strings.Builder
	b.WriteString("Received: from ")
	b.WriteString(traceValue(from, "unknown"))
	if remoteAddr != "" {
		b.WriteString(" (")
		b.WriteString(SanitizeHeaderValue(remoteAddr))
		b.WriteString(")")
	}
	b.WriteString(" by ")
	b.WriteString(traceValue(by, "localhost"))
	b.WriteString(" with ")
	b.WriteString(traceValue(proto, "SMTP"))
	if id != "" {
		b.WriteString(" id ")
		b.WriteString(SanitizeHeaderValue(id))
	}
	if forAddr != "" {
		b.WriteString(" for <")
		b.WriteString(SanitizeHeaderValue(forAddr))
		b.WriteString(">")
	}
	b.WriteString("; ")
	b.WriteString(t.Format(time.RFC1123Z))
	return b.String()
}

func traceValue(v, fallback string) string {
	v = strings.TrimSpace(SanitizeHeaderValue(v))
	if v == "" {
		return fallback
	}
	return v
}

// MessageID generates a unique RFC 5322 Message-ID, angle brackets included.
// The right-hand side is the domain of from when it is a bare addr-spec, then
// hostname, then "localhost", so the value is always syntactically complete.
func MessageID(from, hostname string) string {
	domain := "localhost"
	if addr, ok := NormalizeAddress(from); ok {
		if i := strings.LastIndexByte(addr, '@'); i >= 0 && i+1 < len(addr) {
			domain = addr[i+1:]
		}
	} else if h := strings.TrimSpace(SanitizeHeaderValue(hostname)); h != "" {
		domain = h
	}
	return "<" + newID() + "@" + domain + ">"
}

// HasMessageID reports whether the header block of raw already carries a
// Message-ID header. The scan stops at the blank line that ends the headers, so
// body text cannot be mistaken for one.
func HasMessageID(raw []byte) bool {
	for len(raw) > 0 {
		var line []byte
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			line, raw = raw[:i], raw[i+1:]
		} else {
			line, raw = raw, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			return false
		}
		if len(line) >= len("message-id:") && strings.EqualFold(string(line[:len("message-id:")]), "message-id:") {
			return true
		}
	}
	return false
}

// EnsureMessageID prepends a generated Message-ID to raw unless it already has
// one. Every message is enqueued through it, so a sender cannot leave a message
// without an identifier that bounces and threading can reference.
func EnsureMessageID(raw []byte, from, hostname string) []byte {
	if HasMessageID(raw) {
		return raw
	}
	return PrependHeader(raw, "Message-ID: "+MessageID(from, hostname))
}

// PrependHeader inserts header (without its trailing CRLF) at the top of raw.
func PrependHeader(raw []byte, header string) []byte {
	if header == "" {
		return raw
	}
	out := make([]byte, 0, len(header)+2+len(raw))
	out = append(out, header...)
	out = append(out, '\r', '\n')
	out = append(out, raw...)
	return out
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
	writeHeader(&b, "Message-ID", MessageID(from, ""))
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
	writeHeader(&b, "Message-ID", MessageID(from, ""))
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}
