package caddyemail

import (
	_ "github.com/example/caddy-email/pkg/mta"
	_ "github.com/example/caddy-email/pkg/sendmail"
	_ "github.com/example/caddy-email/pkg/smtp"
)
