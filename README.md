# caddy-email

Imagine sending email was easy again. No wrangling 20 binaries just adding endpoints
to an API. And sending was just as easy calling an API. That is the goal of `caddy-email`.

1. **SMTP API** (`pkg/smtp/`) — accepts incoming mail on ports 25, 587, or whatever.
   STARTTLS, SASL PLAIN, sender/recipient filtering, and routing to Caddy handlers.
2. **Sendmail HTTP handler** (`pkg/sendmail/`) — POST email via API instead of
   installing sendmail like it's 1999.
3. **MTA Worker** (`pkg/mta/`) — outbound delivery queue with MX failover,
   DKIM signing, optional require-TLS, exponential backoff + jitter, partial
   delivery, RFC 3464 bounces delivered back to the sender, and the emotional
   resilience to keep retrying after the 4th deferral.

---

## Quickstart

```bash
xcaddy build --with github.com/frinknet/caddy-email
```

```caddyfile
{
    admin off
    mta { spool_dir /var/lib/caddy/spool }
}
:80 {
    route /sendmail/* { sendmail }
}
```

```bash
curl -X POST http://localhost:80/sendmail/ \
  -H "From: you@example.com" \
  -H "To: friend@example.com" \
  -H "Subject: Hello" \
  -d "SMTP? I barely know her"
# → {"queue_id": "5a3b...7f9c"}
```

Configure a default sender so your web app only needs recipient and body:

```caddyfile
sendmail { from no-reply@example.com }
```

```bash
curl -X POST http://localhost:80/sendmail/ \
  -H "To: user@gmail.com" \
  -d "Thanks for your purchase!"
```

---

## Use Cases

### Outbound transactional email from a web app

POST to `/sendmail/`, the MTA queues it, resolves MX, signs DKIM, delivers.

```caddyfile
{
    mta {
        spool_dir /var/lib/caddy/spool
        dkim {
            selector 2024
            domain example.com
            private_key """-----BEGIN PRIVATE KEY-----..."""
        }
    }
}
:80 {
    route /sendmail/* {
        sendmail { from no-reply@example.com }
    }
}
```

```bash
curl -X POST https://mail.example.com/sendmail/ \
  -H "To: user@gmail.com" \
  -H "Subject: Your order is confirmed" \
  -d "Thanks!"
```

### Inbound email (webhook-style)

Accept SMTP on port 25 and `route` it to your app. Headers carry envelope
metadata, body is the message.

```caddyfile
{
    smtp :25 {
        hostname mx.example.com
        permit_mynetworks 10.0.0.0/8
        route { reverse_proxy localhost:8080 }
    }
}
```

| HTTP status | SMTP reply | Effect |
|---|---|---|
| `200-399` | `250 2.0.0 OK` | Accepted |
| `400-499` | `451 4.4.1` | Sender retries |
| `502/503/504` | `451 4.4.1` | Sender retries |
| `500+` | `550 5.0.0` | Sender bounces |

Return a 4xx when your database is down and the remote MTA will try again.
That's the whole point.

### Port 25 SMTP relay for internal apps

Legacy apps that speak SMTP but you don't want an open relay.

```caddyfile
{
    smtp :25 {
        permit_mynetworks 10.0.0.0/8 172.16.0.0/12
    }
    mta { spool_dir /var/lib/caddy/spool }
}
```

External clients are blocked. Test with swaks:

```bash
swaks --to user@gmail.com --from app@example.com --server 10.0.5.3 --body "hi"
```

### Port 587 submission server

For MUAs (Thunderbird, Outlook, your phone). STARTTLS + auth required.

```caddyfile
{
    smtp :587 {
        tls starttls
        tls_cert_file /etc/letsencrypt/live/mail.example.com/fullchain.pem
        tls_key_file /etc/letsencrypt/live/mail.example.com/privkey.pem
        auth required
        auth_credentials alice s3cret bob hunter2
    }
    mta {
        spool_dir /var/lib/caddy/spool
        dkim {
            selector 2024
            domain example.com
            private_key """-----BEGIN PRIVATE KEY-----..."""
        }
    }
}
```

Port 587 defaults: `tls starttls`, `auth required`. If you set `auth required`
without `auth_credentials`, the module refuses to start. You have been warned.

### Docker

```bash
docker build -t caddy-email .
docker run -d -p 80:80 -p 25:25 \
  -v /path/to/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy-data:/var/lib/caddy \
  caddy-email
```

See the `Dockerfile` for the scratch image — ~5 MB binary, nothing but caddy,
toybox, and a prayer.

---

## Sendmail API Reference

### Request formats

**`text/plain`** (recommended) — metadata in headers, body is the message:

```bash
curl -X POST http://localhost:80/sendmail/ \
  -H "From: alice@example.com" \
  -H "To: bob@example.com" \
  -H "Cc: carol@example.com" \
  -H "Bcc: dave@example.com" \
  -H "Reply-To: replies@example.com" \
  -H "Subject: Hello" \
  -d "World"
```

`Cc` and `Bcc` recipients are added to the envelope and delivered. Only `To`
and `Cc` appear in the message headers — `Bcc` is stripped, per RFC 5321.

**`application/x-www-form-urlencoded`** or **`multipart/form-data`**:

```bash
curl -X POST http://localhost:80/sendmail/ \
  -d "from=alice@example.com" \
  -d "to=bob@example.com" \
  -d "cc=carol@example.com" \
  -d "bcc=dave@example.com" \
  -d "reply-to=replies@example.com" \
  -d "subject=Hello" \
  -d "body=World"
```

Form fields are read from the POST body only; query parameters are ignored.
`from`, `to`, `cc`, `bcc`, and `reply-to` must be valid addresses, and no
field may contain CR or LF. A request that tries to smuggle a header or a
second recipient through a newline is rejected with `400`.

**`message/rfc822`** — raw email, pass-through:

```bash
curl -X POST http://localhost:80/sendmail/ \
  -H "Content-Type: message/rfc822" \
  -H "From: alice@example.com" \
  -H "To: bob@example.com" \
  -d "From: alice\r\nTo: bob\r\nSubject: Hi\r\n\r\nWorld"
```

### Caddyfile

```caddyfile
sendmail {
    from              no-reply@example.com
    default_subject   "No subject"
    max_body_size     31457280
}
```

| Directive | Default | Description |
|---|---|---|
| `from` | — | Default `From` |
| `default_subject` | — | Default `Subject` |
| `max_body_size` | 30 MB | Max request body |
| `allowed_from` | all | Restrict which senders are allowed (`@example.com`) |

### Template function

```gotemplate
{{ sendmail "user@example.com" "Subject" "Body" }}
{{ sendmail "from@example.com" "user@example.com" "Subject" "Body" }}
{{ sendmail dict "to" "u@e.com" "subject" "Hi" "body" "Hello" }}

sendmail {
    from      contact@example.com
    soft_fail           # silently log errors instead of 500ing
}
```

---

## SMTP Server Reference

```caddyfile
{
    smtp :25 {
        hostname            mx.example.com
        tls                 starttls
        tls_cert_file       /etc/certs/fullchain.pem
        tls_key_file        /etc/certs/privkey.pem
        auth                required
        auth_credentials    user1 pass1 user2 pass2
        reject_from         *@spam.com
        reject_rcpt         *@disposable.tld
        max_message_size    26214400
        max_recipients      50
        max_connections     200
        permit_mynetworks   10.0.0.0/8
        deliver_timeout     30s
        route {
            reverse_proxy localhost:8080
        }
    }
}
```

Port defaults:

| Port | TLS | Auth | `permit_mynetworks` |
|---|---|---|---|
| 25 | off | off | `127.0.0.0/8 ::1/128` (block relay) |
| 587 | starttls | required | none |
| other | off | off | none |

- `tls` only accepts `starttls` or `off`. Typos are rejected.
- `auth required` without `auth_credentials` is a hard error.
- Port 25 + `route` without `auth required` = open relay (the module warns).
- Malformed CIDRs in `permit_mynetworks` are logged as warnings.

### What the route handler sees

| Header | Source |
|---|---|
| `From` | MAIL FROM (envelope sender) |
| `To` | RCPT TO (envelope recipients, comma-separated) |
| `Client-Helo` | EHLO/HELO value |
| `Client-IP` | Remote address |
| `Smtp-TLS` | `"true"` if STARTTLS |

Advertised extensions: `SIZE`, `PIPELINING`, `ENHANCEDSTATUSCODES`,
`8BITMIME`, and `STARTTLS` when configured. No `AUTH`: this is a receive-only
listener and all policy belongs to the route. A `552` oversized message is
answered only after the rest of `DATA` is drained, so the remainder of the
body is never parsed as commands.

---

## MTA Reference

### Spool lifecycle

```
Enqueue → incoming/ → Claim → active/ → MX hosts tried in preference order
                          │                       │
                          │ 4xx                   │ 5xx or retries exhausted
                          ▼                       ▼
                     deferred/ ──retry──▶      bounce/ (archive)
                    (backoff + jitter)          + DSN queued to the sender
```

Each job is delivered to a single recipient domain. If a domain's MX lookup
fails temporarily the job is deferred; if the domain publishes a null MX
(RFC 7505) it is bounced immediately. Failed messages are archived in
`bounce/` and an RFC 3464 DSN is enqueued for delivery back to the envelope
sender — bounces are never sent to the null sender `<>`, to another bounce, or
to `MAILER-DAEMON`, so a failure loop is impossible.

### All options

```caddyfile
mta {
    spool_dir           /var/lib/caddy/spool
    hostname            mx.example.com
    concurrency         50           # global delivery goroutines
    per_mx_concurrency  2            # per-MX connections
    max_retries         5            # before bounce
    initial_backoff     5m
    max_backoff         4h
    connect_timeout     15s
    command_timeout     5m
    settle_delay        1s           # wait before picking up new mail
    tick_interval       250ms
    max_batch           1000
    mx_cache_ttl        5m
    require_tls         false        # defer unless the MX offers STARTTLS
    max_spool_bytes     0            # 0 = unlimited; reject new mail above this
    bounce_retention    168h         # prune bounce/ archives older than this
    shutdown_timeout    30s          # cap on waiting for in-flight deliveries
    notify_url          https://hooks.example.com/events
    notify_secret       hush-hush    # HMAC signs webhook payloads
    dkim {
        selector        2024
        domain          example.com
        private_key     """PEM goes here"""
    }
}
```

| Option | Default | Description |
|---|---|---|
| `require_tls` | `false` | Refuse (defer) a host that does not offer STARTTLS |
| `max_spool_bytes` | `0` (unlimited) | Reject new mail once the spool exceeds this many bytes |
| `bounce_retention` | `168h` | Delete `bounce/` archive files older than this |
| `shutdown_timeout` | `30s` | Max time `Stop` waits for in-flight deliveries |

The spool is single-writer: `Start` takes an exclusive lock on `spool_dir` and
refuses to start if another process already holds it, so two Caddy instances
cannot race on the same queue.

### Retry

```
attempt 1: 5m + 0-25% jitter
attempt 2: 10m + jitter
attempt 3: 20m + jitter
attempt 4: 40m + jitter
attempt 5: 80m + jitter
attempt 6: bounced (max_retries exhausted)
```

### Partial delivery

If some RCPTs fail and others succeed, the successful ones get delivered. The
failed ones are re-enqueued as a new deferred job — no innocent recipients
punished for one bad address. If those retries are exhausted too, only the
failed recipients are bounced.

### MX failover

MX hosts are tried in preference order. A host that cannot be reached, does not
complete its greeting, or fails the `require_tls` check is skipped and the next
one is tried; only when every host fails is the job deferred. A domain with no
MX records falls back to its A/AAAA record (implicit MX). A domain that
publishes a null MX (`MX 0 .`, RFC 7505) is treated as permanently
undeliverable and bounced without a delivery attempt.

### DKIM

rsa-sha256, simple/simple canonicalization. DNS record:

```
2024._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=<base64-public-key>"
```

If `dkim.domain` doesn't match the envelope sender domain, the module logs a
warning — your signature will fail verification at the other end.

### Webhook events

Delivered → deferred → bounced. POSTed to `notify_url` as JSON with
`MTA-Signature: sha256=<hmac>` if `notify_secret` is set.

```json
{"queue_id":"5a3b...","event":"delivered","rcpt":["user@gmail.com"],"attempts":1}
{"queue_id":"5a3b...","event":"deferred","rcpt":["user@gmail.com"],"attempts":2,"message":"connect refused","next_at":"..."}
{"queue_id":"5a3b...","event":"bounced","rcpt":["user@bad.com"],"attempts":6,"message":"user unknown"}
```

A job is split so each targets a single recipient domain before delivery, so a
message fanned out across domains produces events under one `queue_id` per
domain. The id returned by `POST /sendmail` is the first domain's.

Fire-and-forget. If your webhook is down, that's your problem now.

### Crash recovery

On startup, stale `active/` files (older than `2 × connect_timeout`) are
moved back to `incoming/` for reprocessing. Because yes, things crash.
Deferred jobs whose `next_at` has passed are swept back into `incoming/` on
every tick, so `deferred/` is a waiting room and not a graveyard.

---

## Troubleshooting

| Error | Fix |
|---|---|
| `port 25 requires explicit permit_mynetworks` | Add `permit_mynetworks` or switch to port 587 |
| `auth=required but no auth_credentials` | Add `auth_credentials user pass` pairs |
| `sendmail requires the mta app` | Add `mta { spool_dir ... }` global block |
| `spool ... is locked by another instance` | Two Caddies share `spool_dir`; give each its own |
| `spool quota exceeded` (503) | Spool is over `max_spool_bytes`; raise it or drain the queue |
| `550 Relay not permitted` | Client IP not in `permit_mynetworks`; use port 587 with auth |
| `invalid tls value` | Only `starttls` and `off` are accepted |
| Messages stuck in `incoming/` | Check MTA logs, DNS resolution, that `mta` block exists |
| DKIM fails verification | Domain mismatch? DNS record wrong? `simple/simple` vs `relaxed/relaxed`? |

---

## Limitations

| What | Status | Deal with it |
|---|---|---|
| Only PLAIN auth | ⏳ | Use STARTTLS |
| Only simple/simple DKIM | ⏳ | May fail with some receivers |
| One DSN per failed job | ⏳ | Lists every failed recipient in one report |
| No MTA-STS / DANE | ⏳ | `require_tls` only enforces opportunistic STARTTLS |
| No metrics endpoint | ⏳ | Use `notify_url` events and logs |
| File attachments in sendmail | ⏳ | Pre-build MIME, POST as `message/rfc822` |
| Queue inspection API | ⏳ | Read files in `spool_dir` |
| IMAP/POP3 | ❌ | This is an MTA, not a boyfriend |