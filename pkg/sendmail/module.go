package sendmail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(Sendmail{})
	httpcaddyfile.RegisterHandlerDirective("sendmail", parseSendmail)
	httpcaddyfile.RegisterDirectiveOrder("sendmail", httpcaddyfile.Before, "file_server")
}

type Sendmail struct {
	DefaultFrom string   `json:"from,omitempty"`
	MaxBodySize int64    `json:"max_body_size,omitempty"`
	AllowedFrom []string `json:"allowed_from,omitempty"`
	RequireAuth bool     `json:"require_auth,omitempty"`

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
	id, err := s.enq.Enqueue(r.Context(), env, raw)
	if err != nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(map[string]string{"queue_id": id})
}

func (s *Sendmail) parseRequest(r *http.Request) (*shared.Envelope, []byte, error) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "message/rfc822"):
		env := &shared.Envelope{
			From: r.Header.Get("X-Envelope-From"),
			To:   []string{r.Header.Get("X-Envelope-To")},
		}
		if env.From == "" {
			env.From = s.DefaultFrom
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("missing envelope-from")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxBodySize))
		if err != nil {
			return nil, nil, err
		}
		return env, body, nil
	case strings.HasPrefix(ct, "multipart/form-data"), strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if err := r.ParseMultipartForm(s.MaxBodySize); err != nil {
			return nil, nil, err
		}
		env := &shared.Envelope{
			From: r.FormValue("from"),
		}
		if env.From == "" {
			env.From = s.DefaultFrom
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("missing from")
		}
		for _, k := range []string{"to", "cc", "bcc"} {
			for _, v := range r.Form[k] {
				for _, one := range strings.Split(v, ",") {
					one = strings.TrimSpace(one)
					if one != "" {
						env.To = append(env.To, one)
					}
				}
			}
		}
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("missing recipients")
		}
		raw := shared.BuildSimple(env.From, env.To, r.FormValue("subject"), r.FormValue("body"))
		return env, raw, nil
	}
	return nil, nil, fmt.Errorf("unsupported content-type: %s", ct)
}
