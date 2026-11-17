package sendmail

import (
	"encoding/json"
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
	return nil
}

func (s *Sendmail) Validate() error { return nil }

func (s *Sendmail) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}
	if s.MaxBodySize > 0 && r.ContentLength > 0 && r.ContentLength > s.MaxBodySize {
		return caddyhttp.Error(http.StatusRequestEntityTooLarge, nil)
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(map[string]string{"queue_id": id})
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
		env := &shared.Envelope{
			From: r.Header.Get("From"),
			To:   []string{r.Header.Get("To")},
		}
		if env.From == "" {
			env.From = s.DefaultFrom
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("missing From header")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxBodySize))
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
		body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxBodySize))
		if err != nil {
			return nil, nil, err
		}
		return s.parseHeaders(r, body)
	}
	return nil, nil, fmt.Errorf("unsupported content-type: %s", ct)
}

func (s *Sendmail) parseForm(r *http.Request) (*shared.Envelope, []byte, error) {
	from := r.FormValue("from")
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		return nil, nil, fmt.Errorf("missing from")
	}

	collect := func(key string) []string {
		var out []string
		for _, v := range r.Form[key] {
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

	replyTo := r.FormValue("reply-to")
	subject := r.FormValue("subject")
	body := r.FormValue("body")

	// Build RFC 5322 message — Bcc is NOT written into headers
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	if len(to) > 0 {
		b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	}
	if len(cc) > 0 {
		b.WriteString("Cc: " + strings.Join(cc, ", ") + "\r\n")
	}
	if replyTo != "" {
		b.WriteString("Reply-To: " + replyTo + "\r\n")
	}
	if subject != "" {
		b.WriteString("Subject: " + subject + "\r\n")
	}
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)

	return env, []byte(b.String()), nil
}

func (s *Sendmail) parseHeaders(r *http.Request, body []byte) (*shared.Envelope, []byte, error) {
	from := r.Header.Get("From")
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		return nil, nil, fmt.Errorf("missing From header")
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

	subject := r.Header.Get("Subject")
	if subject == "" {
		subject = s.DefaultSubject
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
		b.WriteString(name + ": " + v + "\r\n")
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
