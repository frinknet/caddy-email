package sendmail

import (
	"context"
	"fmt"
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/frinknet/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(SendmailTemplateFuncs{})
}

type SendmailTemplateFuncs struct {
	DefaultFrom string `json:"from,omitempty"`
	SoftFail    bool   `json:"soft_fail,omitempty"`

	enq shared.Enqueuer
	log *zap.Logger
}

func (SendmailTemplateFuncs) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.templates.functions.sendmail",
		New: func() caddy.Module { return new(SendmailTemplateFuncs) },
	}
}

func (s *SendmailTemplateFuncs) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	app, err := ctx.App("mta")
	if err != nil {
		return fmt.Errorf("sendmail template functions require the mta app: %w", err)
	}
	enq, err := enqueuerOf(app)
	if err != nil {
		return fmt.Errorf("sendmail template functions require the mta app: %w", err)
	}
	s.enq = enq
	return nil
}

func (s *SendmailTemplateFuncs) CustomTemplateFunctions() template.FuncMap {
	return template.FuncMap{"sendmail": s.send}
}

func (s *SendmailTemplateFuncs) send(args ...any) (string, error) {
	env, raw, err := parseTemplateArgs(args, s.DefaultFrom)
	if err != nil {
		return "", err
	}
	id, err := s.enq.Enqueue(context.Background(), env, raw)
	if err != nil {
		if s.SoftFail {
			s.log.Error("sendmail template", zap.Error(err))
			return "", nil
		}
		return "", fmt.Errorf("sendmail: %w", err)
	}
	return id, nil
}

// parseTemplateArgs accepts positional (to, subject, body) / (from, to, subject, body)
// or a single dict argument with keys from/to/cc/bcc/subject/body.
func parseTemplateArgs(args []any, defaultFrom string) (*shared.Envelope, []byte, error) {
	if len(args) == 1 {
		m, ok := args[0].(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("sendmail: single argument must be a dict")
		}
		env := &shared.Envelope{From: defaultFrom}
		if v, ok := m["from"].(string); ok && v != "" {
			env.From = v
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("sendmail: from required")
		}
		collect := func(key string) []string {
			var out []string
			switch v := m[key].(type) {
			case string:
				if v != "" {
					out = append(out, v)
				}
			case []string:
				out = append(out, v...)
			}
			return out
		}
		to := collect("to")
		cc := collect("cc")
		bcc := collect("bcc")
		env.To = append(env.To, to...)
		env.To = append(env.To, cc...)
		env.To = append(env.To, bcc...)
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("sendmail: recipients required")
		}
		subject, _ := m["subject"].(string)
		body, _ := m["body"].(string)
		replyTo, _ := m["reply_to"].(string)
		if replyTo == "" {
			replyTo, _ = m["reply-to"].(string)
		}
		if err := validateEnvelope(env); err != nil {
			return nil, nil, err
		}
		if replyTo != "" && !shared.ValidAddress(replyTo) {
			return nil, nil, fmt.Errorf("sendmail: invalid reply-to address %q", replyTo)
		}
		if !shared.ValidHeaderValue(subject) {
			return nil, nil, fmt.Errorf("sendmail: subject contains CR or LF")
		}
		// Bcc is kept in the envelope but must not appear in the headers.
		return env, shared.BuildMessage(env.From, to, cc, replyTo, subject, body), nil
	}

	str := func(i int) string {
		if i >= len(args) {
			return ""
		}
		s, _ := args[i].(string)
		return s
	}
	switch len(args) {
	case 3: // to, subject, body
		env := &shared.Envelope{From: defaultFrom, To: []string{str(0)}}
		if env.From == "" {
			return nil, nil, fmt.Errorf("sendmail: from required (no default)")
		}
		if err := validateEnvelope(env); err != nil {
			return nil, nil, err
		}
		return env, shared.BuildSimple(env.From, env.To, str(1), str(2)), nil
	case 4: // from, to, subject, body
		env := &shared.Envelope{From: str(0), To: []string{str(1)}}
		if err := validateEnvelope(env); err != nil {
			return nil, nil, err
		}
		return env, shared.BuildSimple(env.From, env.To, str(2), str(3)), nil
	}
	return nil, nil, fmt.Errorf("sendmail: expected 1 (dict), 3, or 4 arguments; got %d", len(args))
}
