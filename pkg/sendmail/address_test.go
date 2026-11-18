package sendmail

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSendmailEnvelopeDropsDisplayName checks that the envelope carries the
// bare addr-spec while the message header still shows the display name.
func TestSendmailEnvelopeDropsDisplayName(t *testing.T) {
	form := url.Values{
		"from":    {"Alice <alice@test.com>"},
		"to":      {"Bob <bob@test.com>, carol@test.com"},
		"subject": {"Hi"},
		"body":    {"Hello"},
	}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(strings.NewReader(form.Encode())),
	}
	env, raw, err := (&Sendmail{}).parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "alice@test.com" {
		t.Errorf("envelope From = %q, want alice@test.com", env.From)
	}
	want := []string{"bob@test.com", "carol@test.com"}
	if len(env.To) != len(want) {
		t.Fatalf("envelope To = %v, want %v", env.To, want)
	}
	for i := range want {
		if env.To[i] != want[i] {
			t.Errorf("recipient %d = %q, want %q", i, env.To[i], want[i])
		}
	}
	if !strings.Contains(string(raw), "From: Alice <alice@test.com>") {
		t.Errorf("From header lost its display name: %s", raw)
	}
}

// TestSendmailParseHeadersDropsDisplayName covers the text/plain path, where the
// envelope also comes from headers.
func TestSendmailParseHeadersDropsDisplayName(t *testing.T) {
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"Alice <alice@test.com>"},
			"To":           {"Bob <bob@test.com>"},
		},
		Body: io.NopCloser(strings.NewReader("hello")),
	}
	env, _, err := (&Sendmail{}).parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "alice@test.com" {
		t.Errorf("envelope From = %q, want alice@test.com", env.From)
	}
	if len(env.To) != 1 || env.To[0] != "bob@test.com" {
		t.Errorf("envelope To = %v, want [bob@test.com]", env.To)
	}
}
