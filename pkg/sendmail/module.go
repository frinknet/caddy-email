package sendmail

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/frinknet/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(Sendmail{})
	httpcaddyfile.RegisterHandlerDirective("sendmail", parseSendmail)
	httpcaddyfile.RegisterDirectiveOrder("sendmail", httpcaddyfile.Before, "file_server")
}

type Sendmail struct {
	DefaultFrom    string   `json:"from,omitempty"`
	DefaultSubject string   `json:"default_subject,omitempty"`
	MaxBodySize    int64    `json:"max_body_size,omitempty"`
	AllowedFrom    []string `json:"allowed_from,omitempty"`

	enq shared.Enqueuer
	log *zap.Logger
}

func (Sendmail) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.sendmail",
		New: func() caddy.Module { return new(Sendmail) },
	}
}

func (s *Sendmail) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	if s.MaxBodySize == 0 {
		s.MaxBodySize = 30 * 1024 * 1024
	}
	app, err := ctx.App("mta")
	if err != nil {
		return fmt.Errorf("sendmail requires the mta app (add an `mta { ... }` global block): %w", err)
	}
	enq, ok := app.(shared.Enqueuer)
	if !ok {
		return fmt.Errorf("sendmail: mta app does not implement shared.Enqueuer")
	}
	s.enq = enq
	if err := registerMetrics(ctx.GetMetricsRegistry()); err != nil {
		// Observability is not worth failing startup for: log and carry on.
		s.log.Warn("sendmail: metrics registration failed", zap.Error(err))
	}
	return nil
}

func (s *Sendmail) Validate() error { return nil }

func (s *Sendmail) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}
	if s.MaxBodySize > 0 {
		if r.ContentLength > s.MaxBodySize {
			return caddyhttp.Error(http.StatusRequestEntityTooLarge, nil)
		}
		// Cap the body even when Content-Length is absent (chunked), so an
		// oversized streaming upload cannot slip past as a truncated message.
		r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodySize)
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.Is(err, errBodyTooLarge) || errors.As(err, &maxErr) {
			return caddyhttp.Error(http.StatusRequestEntityTooLarge, err)
		}
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	if len(s.AllowedFrom) > 0 {
		if !s.isAllowedSender(env.From) {
			return caddyhttp.Error(http.StatusForbidden, nil)
		}
	}
	id, err := s.enq.Enqueue(r.Context(), env, raw)
	if err != nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, err)
	}
	metricEnqueued.Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(map[string]string{"queue_id": id})
}

// errBodyTooLarge is returned when a request body exceeds MaxBodySize.
var errBodyTooLarge = errors.New("request body exceeds max_body_size")

// readLimited reads a body up to limit bytes and fails instead of silently
// truncating when it is larger. limit <= 0 means unlimited.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(r)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBodyTooLarge
	}
	return data, nil
}

func (s *Sendmail) isAllowedSender(sender string) bool {
	if len(s.AllowedFrom) == 0 {
		return true
	}
	for _, p := range s.AllowedFrom {
		if p == "" {
			continue
		}
		if p[0] == '*' {
			if strings.HasSuffix(sender, p[1:]) {
				return true
			}
		} else if p[0] == '@' {
			if strings.HasSuffix(sender, p) {
				return true
			}
		} else {
			if sender == p {
				return true
			}
			if strings.HasSuffix(sender, "@"+p) {
				return true
			}
		}
	}
	return false
}

func (s *Sendmail) parseRequest(r *http.Request) (*shared.Envelope, []byte, error) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "message/rfc822"):
		from := r.Header.Get("From")
		if from == "" {
			from = s.DefaultFrom
		}
		if from == "" {
			return nil, nil, fmt.Errorf("missing From header")
		}
		env := &shared.Envelope{From: from}
		env.To = append(env.To, splitAddressList(r.Header.Get("To"))...)
		env.To = append(env.To, splitAddressList(r.Header.Get("Cc"))...)
		env.To = append(env.To, splitAddressList(r.Header.Get("Bcc"))...)
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("missing recipients (To, Cc, or Bcc header)")
		}
		if err := validateEnvelope(env); err != nil {
			return nil, nil, err
		}
		body, err := readLimited(r.Body, s.MaxBodySize)
		if err != nil {
			return nil, nil, err
		}
		return env, body, nil
	case strings.HasPrefix(ct, "multipart/form-data"):
		if err := r.ParseMultipartForm(s.MaxBodySize); err != nil {
			return nil, nil, err
		}
		return s.parseForm(r)
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if err := r.ParseForm(); err != nil {
			return nil, nil, err
		}
		return s.parseForm(r)
	case ct == "" || strings.HasPrefix(ct, "text/"):
		body, err := readLimited(r.Body, s.MaxBodySize)
		if err != nil {
			return nil, nil, err
		}
		return s.parseHeaders(r, body)
	}
	return nil, nil, fmt.Errorf("unsupported content-type: %s", ct)
}

// splitAddressList splits a comma-separated address header into individual
// addresses, dropping empty entries.
func splitAddressList(v string) []string {
	var out []string
	for _, one := range strings.Split(v, ",") {
		one = strings.TrimSpace(one)
		if one != "" {
			out = append(out, one)
		}
	}
	return out
}

// validateEnvelope rejects envelope addresses that are empty, unparseable, or
// carry CR/LF. Both the message headers and the SMTP envelope are built from
// these values, so a bad address must fail the request rather than reach the
// wire.
func validateEnvelope(env *shared.Envelope) error {
	if !shared.ValidAddress(env.From) {
		return fmt.Errorf("invalid from address %q", env.From)
	}
	for _, rcpt := range env.To {
		if !shared.ValidAddress(rcpt) {
			return fmt.Errorf("invalid recipient address %q", rcpt)
		}
	}
	return nil
}

func (s *Sendmail) parseForm(r *http.Request) (*shared.Envelope, []byte, error) {
	// PostForm, not Form: query parameters must not be able to set envelope
	// fields or message headers.
	from := r.PostFormValue("from")
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		return nil, nil, fmt.Errorf("missing from")
	}

	collect := func(key string) []string {
		var out []string
		for _, v := range r.PostForm[key] {
			for _, one := range strings.Split(v, ",") {
				one = strings.TrimSpace(one)
				if one != "" {
					out = append(out, one)
				}
			}
		}
		return out
	}

	to := collect("to")
	cc := collect("cc")
	bcc := collect("bcc")

	if len(to) == 0 && len(cc) == 0 && len(bcc) == 0 {
		return nil, nil, fmt.Errorf("missing recipients")
	}

	env := &shared.Envelope{From: from}
	env.To = append(env.To, to...)
	env.To = append(env.To, cc...)
	env.To = append(env.To, bcc...)

	replyTo := r.PostFormValue("reply-to")
	subject := r.PostFormValue("subject")
	body := r.PostFormValue("body")

	if err := validateEnvelope(env); err != nil {
		return nil, nil, err
	}
	if replyTo != "" && !shared.ValidAddress(replyTo) {
		return nil, nil, fmt.Errorf("invalid reply-to address %q", replyTo)
	}
	if !shared.ValidHeaderValue(subject) {
		return nil, nil, fmt.Errorf("invalid subject: contains CR or LF")
	}

	// Build RFC 5322 message — Bcc is NOT written into headers.
	return env, shared.BuildMessage(from, to, cc, replyTo, subject, body), nil
}

func (s *Sendmail) parseHeaders(r *http.Request, body []byte) (*shared.Envelope, []byte, error) {
	from := r.Header.Get("From")
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		return nil, nil, fmt.Errorf("missing From header")
	}
	if !shared.ValidAddress(from) {
		return nil, nil, fmt.Errorf("invalid From header %q", from)
	}

	collect := func(key string) []string {
		var out []string
		for _, v := range strings.Split(r.Header.Get(key), ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	to := collect("To")
	cc := collect("Cc")
	bcc := collect("Bcc")

	env := &shared.Envelope{From: from}
	env.To = append(env.To, to...)
	env.To = append(env.To, cc...)
	env.To = append(env.To, bcc...)
	if len(env.To) == 0 {
		return nil, nil, fmt.Errorf("missing recipients (To, Cc, or Bcc header)")
	}
	if err := validateEnvelope(env); err != nil {
		return nil, nil, err
	}

	subject := r.Header.Get("Subject")
	if subject == "" {
		subject = s.DefaultSubject
	}
	if !shared.ValidHeaderValue(subject) {
		return nil, nil, fmt.Errorf("invalid Subject header: contains CR or LF")
	}

	// Build RFC 5322 message from HTTP headers.
	// Only Bcc is consumed for the envelope and excluded from headers.
	var b strings.Builder

	writeHeader := func(name string) {
		if name == "" {
			return
		}
		v := r.Header.Get(name)
		if v == "" {
			return
		}
		kl := strings.ToLower(name)
		if kl == "bcc" || kl == "content-length" || kl == "host" || kl == "connection" || kl == "transfer-encoding" || kl == "accept" {
			return
		}
		b.WriteString(name + ": " + shared.SanitizeHeaderValue(v) + "\r\n")
	}

	writeHeader("From")
	writeHeader("To")
	writeHeader("Cc")
	writeHeader("Reply-To")
	writeHeader("In-Reply-To")
	writeHeader("References")
	writeHeader("Message-ID")
	writeHeader("Subject")
	writeHeader("Date")
	writeHeader("MIME-Version")
	writeHeader("Content-Type")
	writeHeader("Content-Language")
	writeHeader("Organization")
	writeHeader("Precedence")
	writeHeader("Priority")
	writeHeader("Importance")
	writeHeader("List-ID")
	writeHeader("List-Unsubscribe")
	writeHeader("List-Help")
	writeHeader("List-Archive")
	writeHeader("List-Post")
	writeHeader("Auto-Submitted")
	writeHeader("X-Mailer")
	writeHeader("User-Agent")

	// Ensure required headers
	rawStr := b.String()
	empty := rawStr == ""
	if empty || !strings.Contains(strings.ToLower(rawStr), "date:") {
		b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	}
	if empty || !strings.Contains(strings.ToLower(rawStr), "mime-version:") {
		b.WriteString("MIME-Version: 1.0\r\n")
	}
	if empty || !strings.Contains(strings.ToLower(rawStr), "content-type:") {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	}
	if subject != "" && !strings.Contains(strings.ToLower(rawStr), "subject:") {
		b.WriteString("Subject: " + subject + "\r\n")
	}
	if empty || !strings.Contains(strings.ToLower(rawStr), "from:") {
		b.WriteString("From: " + from + "\r\n")
	}

	b.WriteString("\r\n")
	b.WriteString(string(body))
	return env, []byte(b.String()), nil
}
