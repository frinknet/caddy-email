package sendmail

import (
	"context"
	"fmt"
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
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
	s.enq = app.(shared.Enqueuer)
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
		appendStr := func(v any) {
			if s, ok := v.(string); ok && s != "" {
				env.To = append(env.To, s)
			}
			if sl, ok := v.([]string); ok {
				env.To = append(env.To, sl...)
			}
		}
		appendStr(m["to"])
		appendStr(m["cc"])
		appendStr(m["bcc"])
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("sendmail: recipients required")
		}
		subject, _ := m["subject"].(string)
		body, _ := m["body"].(string)
		return env, shared.BuildSimple(env.From, env.To, subject, body), nil
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
		return env, shared.BuildSimple(env.From, env.To, str(1), str(2)), nil
	case 4: // from, to, subject, body
		env := &shared.Envelope{From: str(0), To: []string{str(1)}}
		return env, shared.BuildSimple(env.From, env.To, str(2), str(3)), nil
	}
	return nil, nil, fmt.Errorf("sendmail: expected 1 (dict), 3, or 4 arguments; got %d", len(args))
}
