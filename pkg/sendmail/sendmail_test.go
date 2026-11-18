package sendmail

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSendmailServeHTTP_RejectsNonPost(t *testing.T) {
	s := &Sendmail{}
	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodGet}
	err := s.ServeHTTP(w, r, nil)
	if err == nil {
		t.Fatal("expected error for non-POST request")
	}
	if !strings.Contains(err.Error(), "405") {
		t.Errorf("expected 405, got %v", err)
	}
}

func TestSendmailServeHTTP_RejectsOversizedChunkedBody(t *testing.T) {
	s := &Sendmail{MaxBodySize: 10}
	w := httptest.NewRecorder()
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"a@b.com"},
			"To":           {"c@d.com"},
		},
		Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 100))),
		// ContentLength -1 models a chunked upload with no declared length.
		ContentLength: -1,
	}
	err := s.ServeHTTP(w, r, nil)
	if err == nil || !strings.Contains(err.Error(), "413") {
		t.Fatalf("expected 413 for oversized chunked body, got %v", err)
	}
}

func TestSendmailParseRequest_Form(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com"}
	body := "from=user@test.com&to=rcpt@test.com&subject=Hello&body=World"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}

	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "user@test.com" {
		t.Errorf("From = %q", env.From)
	}
	if len(env.To) != 1 || env.To[0] != "rcpt@test.com" {
		t.Errorf("To = %v", env.To)
	}
	if !strings.Contains(string(raw), "Subject: Hello") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(string(raw), "World") {
		t.Error("missing body")
	}
}

func TestSendmailParseRequest_FormDefaultFrom(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com"}
	body := "to=rcpt@test.com&subject=Hello&body=World"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}

	env, _, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "default@test.com" {
		t.Errorf("From = %q, want default", env.From)
	}
}

func TestSendmailParseRequest_FormMissingFrom(t *testing.T) {
	s := &Sendmail{}
	body := "to=rcpt@test.com"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}

	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for missing from")
	}
}

func TestSendmailParseRequest_FormMissingRecipients(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com"}
	body := "subject=Hello&body=World"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}

	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for missing recipients")
	}
}

func TestSendmailParseRequest_RFC822(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com", MaxBodySize: 30 * 1024 * 1024}
	rawBody := "From: test@test.com\r\nTo: rcpt@test.com\r\n\r\nhello"

	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"message/rfc822"},
			"From":         {"env@test.com"},
			"To":           {"rcpt@test.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(rawBody))),
	}

	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "env@test.com" {
		t.Errorf("From = %q", env.From)
	}
	if string(raw) != rawBody {
		t.Errorf("raw body mismatch:\ngot:  %q\nwant: %q", string(raw), rawBody)
	}
}

func TestSendmailParseRequest_UnsupportedContentType(t *testing.T) {
	s := &Sendmail{}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/json"}},
	}

	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for unsupported content type")
	}
}

func TestSendmailParseRequest_TextPlain(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com", DefaultSubject: "Default Subj", MaxBodySize: 30 * 1024 * 1024}
	body := "Hello World"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"sender@test.com"},
			"To":           {"rcpt1@test.com, rcpt2@test.com"},
			"Subject":      {"Test Subject"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(body))),
	}

	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "sender@test.com" {
		t.Errorf("From = %q", env.From)
	}
	if len(env.To) != 2 || env.To[0] != "rcpt1@test.com" || env.To[1] != "rcpt2@test.com" {
		t.Errorf("To = %v", env.To)
	}
	if !strings.Contains(string(raw), "Subject: Test Subject") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(string(raw), "Hello World") {
		t.Error("missing body")
	}
}

func TestSendmailParseRequest_TextPlainDefaults(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com", DefaultSubject: "Default Subj", MaxBodySize: 30 * 1024 * 1024}
	body := "Hello World"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"To":           {"rcpt@test.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(body))),
	}

	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "default@test.com" {
		t.Errorf("From = %q, want default", env.From)
	}
	if !strings.Contains(string(raw), "Subject: Default Subj") {
		t.Error("missing DefaultSubject header")
	}
}

func TestSendmailParseRequest_TextPlainMissingFrom(t *testing.T) {
	s := &Sendmail{MaxBodySize: 30 * 1024 * 1024}
	body := "Hello"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"To":           {"rcpt@test.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(body))),
	}
	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for missing from")
	}
}

func TestSendmailParseRequest_TextPlainMissingTo(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"a@b.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for missing to")
	}
}

func TestSendmailParseRequest_EmptyContentType(t *testing.T) {
	s := &Sendmail{DefaultFrom: "default@test.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From":    {"a@b.com"},
			"To":      {"c@d.com"},
			"Subject": {"Hi"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "a@b.com" {
		t.Errorf("From = %q", env.From)
	}
	if !strings.Contains(string(raw), "Subject: Hi") {
		t.Error("missing Subject header")
	}
}

func TestSendmailParseRequest_CcAndBcc(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"From":         {"a@b.com"},
			"To":           {"b@b.com"},
			"Cc":           {"c@c.com, c2@c2.com"},
			"Bcc":          {"d@d.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	// All recipients in envelope (to + cc + bcc)
	if len(env.To) != 4 {
		t.Fatalf("expected 4 envelope recipients, got %d: %v", len(env.To), env.To)
	}
	// To and Cc in headers, Bcc NOT in headers
	if !strings.Contains(string(raw), "To: b@b.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(string(raw), "Cc: c@c.com, c2@c2.com") {
		t.Error("missing Cc header")
	}
	if strings.Contains(string(raw), "d@d.com") {
		t.Error("Bcc leaked into message headers")
	}
}

func TestSendmailParseRequest_CcOnly(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From": {"a@b.com"},
			"Cc":   {"c@c.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	env, _, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if len(env.To) != 1 || env.To[0] != "c@c.com" {
		t.Errorf("expected 1 envelope recipient from Cc, got %v", env.To)
	}
}

func TestSendmailParseRequest_BccOnly(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From": {"a@b.com"},
			"Bcc":  {"d@d.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if len(env.To) != 1 || env.To[0] != "d@d.com" {
		t.Errorf("expected 1 envelope recipient from Bcc, got %v", env.To)
	}
	// No To or Cc headers when only Bcc
	if strings.Contains(string(raw), "To:") {
		t.Error("To header present with only Bcc")
	}
	if strings.Contains(string(raw), "Cc:") {
		t.Error("Cc header present with only Bcc")
	}
	if strings.Contains(string(raw), "d@d.com") {
		t.Error("Bcc leaked into message headers")
	}
}

func TestSendmailParseRequest_ReplyTo(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com", MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From":     {"a@b.com"},
			"To":       {"b@b.com"},
			"Reply-To": {"support@example.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	_, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if !strings.Contains(string(raw), "Reply-To: support@example.com") {
		t.Error("missing Reply-To header")
	}
}

func TestSendmailParseRequest_FormCcBccReplyTo(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com"}
	body := "from=a@b.com&to=b@b.com&cc=c@c.com&bcc=d@d.com&reply-to=support@x.com&subject=Hi&body=hello"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if len(env.To) != 3 {
		t.Errorf("expected 3 envelope recipients, got %d", len(env.To))
	}
	if !strings.Contains(string(raw), "Cc: c@c.com") {
		t.Error("missing Cc in message")
	}
	if strings.Contains(string(raw), "d@d.com") {
		t.Error("Bcc leaked into message")
	}
	if !strings.Contains(string(raw), "Reply-To: support@x.com") {
		t.Error("missing Reply-To in message")
	}
}

func TestSendmailParseRequest_FormSubjectHeaderInjection(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com"}
	// %0d%0a decodes to CRLF, which would otherwise start a new header.
	body := "to=c@d.com&subject=Hi%0d%0aBcc%3A%20evil@x.com&body=x"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}
	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for CRLF in subject")
	}
}

func TestSendmailParseRequest_FormAddressHeaderInjection(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com"}
	body := "to=c@d.com%0d%0aBcc%3A%20evil@x.com&body=x"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}
	_, _, err := s.parseRequest(r)
	if err == nil {
		t.Fatal("expected error for CRLF in recipient address")
	}
}

func TestSendmailParseRequest_FormInvalidAddress(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com"}
	body := "to=not-an-address&body=x"
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte(body))),
	}
	if _, _, err := s.parseRequest(r); err == nil {
		t.Fatal("expected error for invalid recipient address")
	}
}

func TestSendmailParseRequest_FormIgnoresQueryParams(t *testing.T) {
	s := &Sendmail{DefaultFrom: "a@b.com"}
	// The envelope sender must come from the POST body, not the query string.
	r := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{RawQuery: "from=attacker@evil.com"},
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(bytes.NewReader([]byte("to=c@d.com&body=x"))),
	}
	env, _, err := s.parseRequest(r)
	if err != nil {
		t.Fatalf("parseRequest: %v", err)
	}
	if env.From != "a@b.com" {
		t.Errorf("From = %q, want the configured default", env.From)
	}
}

func TestSendmailParseRequest_HeaderAddressInjection(t *testing.T) {
	s := &Sendmail{MaxBodySize: 30 * 1024 * 1024}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From": {"a@b.com\r\nBcc: evil@x.com"},
			"To":   {"c@d.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	if _, _, err := s.parseRequest(r); err == nil {
		t.Fatal("expected error for CRLF in From header")
	}
}

func TestSendmailAllowedFrom(t *testing.T) {
	s := &Sendmail{
		AllowedFrom: []string{"@example.com", "admin@test.com"},
		MaxBodySize: 30 * 1024 * 1024,
	}
	// Blocked sender
	if s.isAllowedSender("spam@evil.com") {
		t.Error("spam@evil.com should be blocked")
	}
	if s.isAllowedSender("admin@other.com") {
		t.Error("admin@other.com should be blocked")
	}
	// Allowed senders
	if !s.isAllowedSender("user@example.com") {
		t.Error("user@example.com should be allowed")
	}
	if !s.isAllowedSender("admin@test.com") {
		t.Error("admin@test.com should be allowed")
	}
}

func TestSendmailAllowedFromHTTP(t *testing.T) {
	s := &Sendmail{
		AllowedFrom: []string{"@example.com"},
		MaxBodySize: 30 * 1024 * 1024,
	}
	r := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"From": {"spam@evil.com"},
			"To":   {"c@d.com"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	w := httptest.NewRecorder()
	err := s.ServeHTTP(w, r, nil)
	if err == nil {
		t.Fatal("expected error for disallowed sender")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403, got %v", err)
	}
}

func TestSendmailParseTemplateDictCcBcc(t *testing.T) {
	args := []any{map[string]any{
		"from":     "a@b.com",
		"to":       "b@b.com",
		"cc":       "c@c.com",
		"bcc":      "d@d.com",
		"reply_to": "r@r.com",
		"subject":  "Hi",
		"body":     "Hello",
	}}
	env, raw, err := parseTemplateArgs(args, "default@b.com")
	if err != nil {
		t.Fatalf("parseTemplateArgs: %v", err)
	}
	if len(env.To) != 3 {
		t.Errorf("expected 3 envelope recipients, got %d", len(env.To))
	}
	s := string(raw)
	if !strings.Contains(s, "To: b@b.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(s, "Cc: c@c.com") {
		t.Error("missing Cc header")
	}
	if strings.Contains(s, "d@d.com") {
		t.Error("Bcc leaked into message headers")
	}
	if !strings.Contains(s, "Reply-To: r@r.com") {
		t.Error("missing Reply-To header")
	}
}
