package smtp

import (
	"strings"
	"testing"
)

func TestForwardHeader(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"From":                  true,
		"Subject":               true,
		"Message-ID":            true,
		"Subject ":              true,
		"List-Unsubscribe":      true,
		"list-id":               true,
		"X-Spam-Status":         true,
		"X-Virus-Scanned":       true,
		"ARC-Seal":              true,
		"Authorization":         false,
		"Cookie":                false,
		"Content-Length":        false,
		"Host":                  false,
		"Connection":            false,
		"Transfer-Encoding":     false,
		"X-Forwarded-For":       false,
		"X-Forwarded-Host":      false,
		"X-Envelope-From":       false,
		"X-Client-IP":           false,
		"X-Smtp-TLS":            false,
		"Proxy-Authorization":   false,
		"X-Foo":                 false,
		"not-a-real-header-abc": false,
	} {
		if got := forwardHeader(name); got != want {
			t.Errorf("forwardHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestBuildRequestHeaderAllowlist(t *testing.T) {
	t.Parallel()
	s := newSession(&ListenerConfig{Hostname: "mail.test"}, newFakeConn())
	s.helo = "test"
	s.from = "a@b"
	s.rcpts = []string{"c@d"}

	raw := []byte("From: sender@example.com\r\n" +
		"Subject: hi\r\n" +
		"List-Unsubscribe: <mailto:unsub@example.com>\r\n" +
		"X-Spam-Status: No\r\n" +
		"Authorization: Bearer evil\r\n" +
		"Cookie: session=evil\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"X-Forwarded-Host: evil.example\r\n" +
		"Content-Length: 999999\r\n" +
		"Host: evil.example\r\n" +
		"Connection: close\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"X-Envelope-From: attacker@evil.example\r\n" +
		"X-Client-IP: 1.2.3.4\r\n" +
		"\r\n" +
		"body\r\n")

	req := s.buildRequest(raw)

	for name, want := range map[string]string{
		"From":             "sender@example.com",
		"Subject":          "hi",
		"List-Unsubscribe": "<mailto:unsub@example.com>",
		"X-Spam-Status":    "No",
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("Header.Get(%q) = %q, want %q", name, got, want)
		}
	}

	for _, name := range []string{
		"Authorization", "Cookie", "X-Forwarded-For", "X-Forwarded-Host",
		"Host", "Connection", "Transfer-Encoding",
	} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("sender-controlled %s leaked into request: %q", name, got)
		}
	}

	if got := req.Header.Get("X-Envelope-From"); got != "a@b" {
		t.Errorf("X-Envelope-From = %q, want envelope sender a@b", got)
	}
	if got := req.Header.Get("X-Client-IP"); got != "127.0.0.1:12345" {
		t.Errorf("X-Client-IP = %q, want connection address", got)
	}
	if want := int64(len("body\r\n")); req.ContentLength != want {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, want)
	}
	if !strings.Contains(req.Host, "mail.test") {
		t.Errorf("Host = %q, want configured hostname", req.Host)
	}
}
