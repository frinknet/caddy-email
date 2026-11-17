package shared

import (
	"bytes"
	"strings"
	"time"
)

// BuildSimple constructs a minimal RFC 5322 text/plain message.
// TODO: multipart, attachments, HTML.
func BuildSimple(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	if subject != "" {
		b.WriteString("Subject: " + subject + "\r\n")
	}
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}