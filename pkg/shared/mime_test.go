package shared

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"a@b.com", "a@b.com", true},
		{"Name <a@b.com>", "a@b.com", true},
		{"\"A B\" <a@b.com>", "a@b.com", true},
		{"<a@b.com>", "a@b.com", true},
		{"", "", false},
		{"no-at-sign", "", false},
		{"a@b\r\nX-Injected: 1", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeAddress(tc.in)
		if ok != tc.ok {
			t.Errorf("NormalizeAddress(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("NormalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidAddressStillAcceptsDisplayName(t *testing.T) {
	// ValidAddress is about well-formedness, not envelope form; NormalizeAddress
	// is what callers use to strip the display name.
	if !ValidAddress("Name <a@b.com>") {
		t.Error("ValidAddress should accept a display-name address")
	}
}

func TestReceivedHeader(t *testing.T) {
	got := ReceivedHeader("helo.example", "192.0.2.1", "mail.example", "ESMTPS", "id123", "u@example.com", fixedTime)
	for _, want := range []string{
		"Received: from helo.example",
		"(192.0.2.1)",
		"by mail.example",
		"with ESMTPS",
		"id id123",
		"for <u@example.com>",
		fixedTime.Format(time.RFC1123Z),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ReceivedHeader missing %q: %s", want, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("ReceivedHeader must not contain CR or LF: %q", got)
	}
}

func TestReceivedHeaderDefaultsAndSanitizes(t *testing.T) {
	got := ReceivedHeader("", "", "", "", "", "", fixedTime)
	if !strings.Contains(got, "from unknown") || !strings.Contains(got, "by localhost") || !strings.Contains(got, "with SMTP") {
		t.Errorf("ReceivedHeader did not fill defaults: %s", got)
	}
	if strings.Contains(got, "id ") || strings.Contains(got, "for <") {
		t.Errorf("ReceivedHeader emitted empty id/for: %s", got)
	}
	inj := ReceivedHeader("evil\r\nX-Injected: 1", "", "mail.example", "ESMTP", "", "", fixedTime)
	if strings.Contains(inj, "\r\nX-Injected") {
		t.Errorf("ReceivedHeader allowed header injection: %q", inj)
	}
}

func TestPrependHeader(t *testing.T) {
	raw := []byte("From: a@b\r\n\r\nbody")
	got := string(PrependHeader(raw, "Received: from x by y"))
	want := "Received: from x by y\r\nFrom: a@b\r\n\r\nbody"
	if got != want {
		t.Errorf("PrependHeader = %q, want %q", got, want)
	}
	if got := PrependHeader(raw, ""); string(got) != string(raw) {
		t.Error("PrependHeader with empty header must not change the message")
	}
}
