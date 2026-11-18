# caddy-email

Imagine sending email was easy again. No wrangling 20 binaries just adding endpoints
to an API. And sending was just as easy calling an API. That is the goal of `caddy-email`.

`caddy-email` is transactional mail in and out, not a full mail system. It does
two things, and only two:

1. **Inbound** (`pkg/smtp/`) — receives mail, full stop. It accepts a message on
   ports 25, 587, or whatever, optionally upgrades with STARTTLS, and hands the
   parsed message to a Caddy route. It is receive-only: it never stores mail,
   never serves it back, and never forwards it onward.
2. **Outbound** (`pkg/sendmail/` + `pkg/mta/`) — sends mail, full stop. The
   `sendmail` HTTP handler spools a message via API instead of installing
   sendmail like it's 1999; the `mta` worker delivers it directly via MX
   failover, or relays it to a configured smarthost (`relay`), with DKIM
   signing, optional require-TLS, exponential backoff + jitter, partial
   delivery, and RFC 3464 bounces to the sender.

There is no mailbox: no POP3, no IMAP, no message store, and no retrieval.
Inbound mail is never forwarded onward; outbound mail is delivered directly or
relayed to a smarthost. If you want a mail server users log into and read, this
is not it.

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
metadata, body is the message. The listener only receives: it has no mailbox and
no forwarding, so each message lives or dies by what your route does with it.

```caddyfile
{
    smtp :25 {
        hostname mx.example.com
        max_connections 200
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

Legacy apps that speak SMTP but you don't want an open relay. The listener has
no relay policy of its own: it accepts, parses, and hands every message to the
route, so decide there, by matching the client address:

```caddyfile
{
    smtp :25 {
        route {
            @internal remote_ip 10.0.0.0/8 172.16.0.0/12
            reverse_proxy @internal localhost:8080
            respond "Relay not permitted" 550
        }
    }
    mta { spool_dir /var/lib/caddy/spool }
}
```

External clients get `550` and never reach your app. Test with swaks:

```bash
swaks --to user@gmail.com --from app@example.com --server 10.0.5.3 --body "hi"
```

### Port 587 with STARTTLS

Encrypt the session for clients that support it. There is no `AUTH`: the
listener is receive-only and never advertises it, so a client is allowed by the
route, not by credentials.

```caddyfile
{
    smtp :587 {
        tls starttls
        tls_cert_file /etc/letsencrypt/live/mail.example.com/fullchain.pem
        tls_key_file /etc/letsencrypt/live/mail.example.com/privkey.pem
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

`tls` accepts only `starttls` or `off`, and `off` is the default on every port.
With `starttls`, a certificate is required and the session upgrades in place
when the client sends `STARTTLS`.

### Docker

```bash
docker build -t caddy-email .
docker run -d -p 80:80 -p 25:25 \
  -v /path/to/Caddyfile:/srv/www/Caddyfile \
  -v caddy-data:/var/lib/caddy \
  caddy-email
```

See the `Dockerfile` for the scratch image — ~5 MB binary, nothing but caddy,
toybox, and a prayer. The image loads `/srv/www/Caddyfile`, which is the
default config shipped in `www/`. To check a built image end to end, run
`tests/e2e/container.sh <image>`; it boots the image and exercises the SMTP
route header allowlist, the sendmail handler, and the metrics endpoint.

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
| `from` | none | Default `From` when the request omits one |
| `default_subject` | none | Default `Subject` when the request omits one |
| `max_body_size` | 30 MB | Max request body; anything larger gets `413` |
| `allowed_from` | all allowed | Sender allowlist; a non-match gets `403` |

`allowed_from` takes one or more patterns, matched against the envelope sender:

| Pattern | Matches |
|---|---|
| `user@example.com` | That exact sender |
| `example.com` or `@example.com` | Any sender in that domain |
| `*example.com` | Any sender in that domain or a subdomain |

Matching is case-insensitive, and domain patterns match whole domains:
`*example.com` does not admit `attacker@notexample.com`.

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
        max_message_size    26214400
        max_recipients      50
        max_connections     200
        deliver_timeout     30s
        route {
            reverse_proxy localhost:8080
        }
    }
}
```

| Option | Default | Description |
|---|---|---|
| `hostname` | system hostname | Name used in the greeting and the `EHLO` reply |
| `tls` | `off` | `starttls` or `off`; anything else is rejected |
| `tls_cert_file` | none | Certificate chain; required when `tls starttls` |
| `tls_key_file` | none | Private key; required when `tls starttls` |
| `max_message_size` | 25 MiB | A `DATA` body past this is rejected with `552` |
| `max_recipients` | 50 | The 51st `RCPT TO` is rejected with `452` |
| `max_connections` | 200 | Concurrent connections; further clients wait |
| `deliver_timeout` | 30s | Read and write deadline, and the idle-session cap |
| `route` | none | Caddy route the parsed message is handed to |

The block is repeatable, so `smtp :25 { ... }` and `smtp :587 { ... }` declare
two independent listeners.

There are no port-specific defaults. Every listener starts with `tls off`, no
authentication, and no relay policy. `route` is optional, and a listener without
one accepts every message with `250`. Relaying, sender filtering, and recipient
filtering are all decisions for the route, which is what the port 25 relay
example above does with a `remote_ip` matcher.

### What the route handler sees

| Header | Source |
|---|---|
| `From` | MAIL FROM (envelope sender) |
| `To` | RCPT TO (envelope recipients, comma-separated) |
| `Client-Helo` | EHLO/HELO value |
| `Client-IP` | Remote address |
| `Smtp-TLS` | `"true"` if STARTTLS |

Message headers are also forwarded, but only from an allowlist: standard
envelope and content headers plus `List-*`, `ARC-*`, `X-Spam-*`, and
`X-Virus-*`. Anything else, including `Authorization`, `Cookie`,
`Content-Length`, and `X-Forwarded-For`, is dropped so a sender cannot inject
HTTP-level headers into a `reverse_proxy` route.

Advertised extensions: `SIZE`, `PIPELINING`, `ENHANCEDSTATUSCODES`,
`8BITMIME`, and `STARTTLS` when configured. No `AUTH`: this is a receive-only
listener and all policy belongs to the route. A `552` oversized message is
answered only after the rest of `DATA` is drained, so the remainder of the
body is never parsed as commands.

### Placeholders

The synthesized request carries a Caddy replacer, so the route can read session
state with `{smtp.*}`:

| Placeholder | Value |
|---|---|
| `{smtp.remote_ip}` | Client address |
| `{smtp.local_ip}` | Local address |
| `{smtp.hostname}` | Configured `hostname` |
| `{smtp.helo}` | `EHLO`/`HELO` argument |
| `{smtp.from}` | `MAIL FROM` address |
| `{smtp.rcpt}` | Most recent `RCPT TO` address |
| `{smtp.rcpts}` | Every `RCPT TO` collected so far |
| `{smtp.tls}` | `true` once `STARTTLS` has completed |

### Session flow

A normal SMTP dialogue. `EHLO`/`HELO` records the client name (visible as
`{smtp.helo}`), `MAIL FROM:<addr>` sets the sender (`MAIL FROM:<>`, the null
sender, is accepted), one or more `RCPT TO:<addr>` set the recipients, and
`DATA` collects the body until a lone `.` line, with leading dots unescaped
(`..` becomes `.`). `RSET` clears the current transaction, `NOOP` does nothing,
`QUIT` ends the session, and an unrecognized command gets `500`. `DATA` before
`MAIL` or `RCPT` gets `503`.

Reads are bounded by `deliver_timeout`, rearmed before every read, so an idle
client is dropped but a slow-but-active transfer is not, and a single line is
capped so an unterminated line cannot exhaust memory. Past `max_message_size` the
listener answers `552` and then drains the rest of `DATA`, so trailing body lines
are never misparsed as commands; a client that keeps streaming is disconnected.
`STARTTLS` is refused once a transaction is open or TLS is already active, and
the handshake discards the pre-TLS session state.

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
    relay               kumo.internal:2525  # forward everything to a smarthost
    max_spool_bytes     0            # 0 = unlimited; reject new mail above this
    bounce_retention    168h         # prune bounce/ and corrupt/ archives older than this
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
| `relay` | none | Forward all mail to this `host[:port]` instead of resolving MX |
| `max_spool_bytes` | `0` (unlimited) | Reject new mail once the spool exceeds this many bytes |
| `bounce_retention` | `168h` | Delete `bounce/` and `corrupt/` archive files older than this |
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

### Relay (smarthost)

Set `relay` to forward every outbound message to a single downstream MTA
instead of resolving MX and delivering directly. This is the mode for handing
all mail to a dedicated queueing and delivery engine such as KumoMTA:

```caddyfile
mta {
    spool_dir /var/lib/caddy/spool
    relay     kumo.internal:2525
}
```

With a relay configured:

- MX lookup is skipped entirely, so no DNS is done for recipient domains.
- `per_mx_concurrency` limits connections to the smarthost as a whole (it is a
  single target), which is the knob to match the downstream server's limits.
- Multi-domain jobs are not split, since every recipient shares one target.
- Opportunistic STARTTLS still applies, and `require_tls` still defers when the
  smarthost offers no STARTTLS.
- DKIM signing, retries/backoff, bounces, and webhooks are unchanged.

The port defaults to 25. Authentication to the smarthost is not implemented;
run the relay on a trusted network, or front it with something that adds auth.

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

Stale `active/` entries (older than `2 × connect_timeout`) are moved back to
`incoming/` for reprocessing, both at startup and on every janitor pass, so a
job claimed moments before a crash is not stranded. A pair split by a crash
between its two file moves is reunited (the body `df` is the leader and `qf` is
moved to join it), an orphan body from an interrupted enqueue is removed, and a
`qf` with no body is quarantined. Deferred jobs whose `next_at` has passed are
swept back into `incoming/` on every tick, so `deferred/` is a waiting room and
not a graveyard. Because yes, things crash.

---

## Capacity

These are measured microbenchmarks, not end-to-end load tests. They isolate the
per-message CPU and disk costs so you can reason about where the ceiling is
before you point real mail at it.

Measured with `go test ./pkg/... -run '^$' -bench . -benchmem` inside the
`caddy:2.11.9-builder-alpine` container (Go 1.27.4) on a 12th Gen Intel
i3-1215U (8 threads), with the spool on the container's overlay filesystem:

| Stage | Cost | Implied ceiling |
|---|---|---|
| Spool ingest (`Enqueue`, 2× fsync) | ~8.7 ms/message | ~115 msg/s, single stream |
| Queue scan (`ScanEligible`) | ~10 µs/job | 1000-job backlog ≈ 10 ms per tick |
| Dispatch (`scan` + `claim` + `unlink`) | ~126 µs/job | ~8,000 msg/s |
| MIME build (`BuildMessage`) | ~0.9 µs/message | negligible |
| SMTP command parsing (full session) | ~7.5 µs/session | ~133,000 sessions/s/core |
| DKIM sign (RSA-2048), serial | ~0.7-0.9 ms/message | ~1,100-1,400 msg/s/core |
| DKIM sign (RSA-2048), parallel | ~0.24-0.37 ms/message | ~2,700-4,200 msg/s total |

**Spool ingest is bound by `fsync`, not by this code.** The identical benchmark
measured ~81 µs/message (~12,000 msg/s) on a host SSD and ~8.7 ms/message
(~115 msg/s) on the container's overlay filesystem: a ~100× swing that is
entirely the storage layer. Treat that row as "measure your own disk". The
CPU-bound rows are stable across environments.

**What actually limits you**

1. **Whether storage or DKIM dominates depends on your disk.** DKIM signing is a
   fixed ~0.7-0.9 ms of CPU per RSA-2048 message; the spool `fsync` is
   storage-dependent (81 µs on an SSD, 8.7 ms on overlayfs). Fast storage makes
   DKIM the bottleneck; slow storage makes `fsync` the bottleneck. Signing
   parallelizes across cores but only ~3× on this 8-thread box (RSA private-key
   ops are core-bound and the low-power cores pull their weight slowly), so
   expect thousands of signed messages/second, not tens of thousands. Raise
   `concurrency` to use more cores.
2. **Outbound SMTP round trips dominate in practice.** Real throughput is set by
   how fast your recipients' MX servers accept mail, which no local benchmark
   can tell you. `per_mx_concurrency` (default 2) is the knob for a single busy
   destination; with `relay` set it limits connections to the smarthost.
3. **Scan cost grows with queue depth.** A deep backlog costs a linear scan each
   tick; keep `tick_interval` and `max_batch` sized so one tick drains what it
   scans.

**Knobs that move the numbers**

| Goal | Setting |
|---|---|
| More parallel deliveries | `concurrency` (default 50) |
| More connections to one MX (or the relay) | `per_mx_concurrency` (default 2) |
| Faster backlog drain | lower `settle_delay`, raise `max_batch` |
| Bound memory/scan cost | lower `max_batch` on a huge queue |

Reproduce or re-measure on your own hardware before sizing a deployment; disk
`fsync` latency in particular varies wildly between a local SSD, a network
volume, and a container overlay.

---

## Metrics

Every module registers Prometheus metrics into Caddy's metrics registry, the
same one Caddy serves from its admin `/metrics` endpoint. No extra
configuration is needed: if your Caddy build exposes metrics, these show up
alongside Caddy's own.

With the admin API enabled (the default), scrape the built-in endpoint:

```bash
curl -s localhost:2019/metrics | grep caddy_email
```

If you run `admin off`, mount Caddy's `metrics` handler on a route instead:

```caddyfile
:9090 {
    metrics
}
```

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `caddy_email_mta_events_total` | counter | `event` (`delivered`, `deferred`, `bounced`) | Delivery outcomes emitted by the queue |
| `caddy_email_mta_enqueued_total` | counter | | Messages accepted into the spool |
| `caddy_email_mta_notify_dropped_total` | counter | | Webhook events dropped because the buffer was full |
| `caddy_email_mta_spool_bytes` | gauge | | Bytes held by the spool directory |
| `caddy_email_mta_spool_jobs` | gauge | `state` (`incoming`, `active`, `deferred`, `bounce`, `corrupt`, `hold`) | Queued jobs by spool state |
| `caddy_email_smtp_connections_total` | counter | | Inbound SMTP connections accepted |
| `caddy_email_smtp_messages_total` | counter | | Inbound messages accepted by the route |
| `caddy_email_sendmail_enqueued_total` | counter | | Messages accepted by the sendmail HTTP API |

The `spool_jobs` and `spool_bytes` gauges are computed at scrape time from a
single walk of the spool, so they are always exact; a scrape on a very large
spool costs one directory walk. The counters are exact.

---

## Troubleshooting

| Error | Fix |
|---|---|
| `unknown smtp option: auth` | The listener has no AUTH; filter in the route instead |
| `unknown sendmail option: ...` | Only `from`, `default_subject`, `max_body_size`, `allowed_from` exist |
| `sendmail requires the mta app` | Add an `mta { spool_dir ... }` global block |
| `sendmail template functions require the mta app` | Same: the template function needs the `mta` app |
| `spool ... is locked by another instance` | Two Caddies share `spool_dir`; give each its own |
| `spool quota exceeded` (503) | Spool is over `max_spool_bytes`; raise it or drain the queue |
| `invalid tls value` | Only `starttls` and `off` are accepted |
| `tls=starttls requires tls_cert_file and tls_key_file` | Set both, or use `tls off` |
| `invalid relay` | `relay` needs a host: `host:port` or `host` |
| Messages stuck in `incoming/` | Check MTA logs, DNS resolution, and that the `mta` block exists |
| Mail accepted but never delivered | Check `relay`/DNS reachability and the per-MX semaphore (`per_mx_concurrency`) |

---

## Limitations

| What | Status | Deal with it |
|---|---|---|
| Not a full mail system | ❌ | No mailbox: inbound goes to a route, outbound goes to the wire |
| Mail forwarding | ❌ | Inbound mail is handed to your route; nothing relays it onward |
| No SMTP `AUTH` | ⏳ | The listener is receive-only; gate in the route |
| No relay policy on the listener | ⏳ | Match `remote_ip` in the route |
| Only simple/simple DKIM | ⏳ | May fail with some receivers |
| One DSN per failed job | ⏳ | Lists every failed recipient in one report |
| No MTA-STS / DANE | ⏳ | `require_tls` only enforces opportunistic STARTTLS |
| No relay authentication | ⏳ | `relay` sends unauthenticated; front it with an auth proxy |
| Metrics endpoint | ✅ | Exposed on Caddy's `/metrics`; see Metrics |
| File attachments in sendmail | ⏳ | Pre-build MIME, POST as `message/rfc822` |
| Queue inspection API | ⏳ | Read files in `spool_dir` |
| `Received:` tracing | ✅ | SMTP intake and outbound delivery each prepend a trace header |
| IMAP/POP3 | ❌ | This is an MTA, not a boyfriend |