# `caddy-email` Technical Specification

> **Status:** this is the design document, kept in step with the implementation.
> Everything below describes what the code does today, except the items
> collected under "Not yet built" at the end, which are deliberate omissions.
> `README.md` is the user-facing guide; where this document and the code
> disagree, the code is right. Known defects are tracked in `BACKLOG.md`, not
> here.

**Module IDs:**

* `mta` (global option `mta`; the outbound queue and delivery engine. It is a
  Caddy app and implements `shared.Enqueuer`)
* `smtp` (global option `smtp`; the inbound SMTP listener app)
* `http.handlers.sendmail` (HTTP handler and Caddyfile directive for accepting
  mail over HTTP)
* `http.handlers.templates.functions.sendmail` (Caddy `templates` extension
  that queues mail from a template)

**Purpose:** make sending and receiving mail in Caddy a config block and an
endpoint, not a stack of daemons. `sendmail` and the `smtp` listener are thin
adapters: they parse a message and hand it to a route, or to the `mta` queue.
The `mta` app owns the durable spool, retries, DKIM, bounces, and delivery.

---

## 1. Architecture & Execution Pipeline

Four packages, one root:

* `pkg/shared` (`shared`) holds the pieces every other package needs: the spool
  format and its atomic file operations, MIME message construction, address and
  header validation, and HMAC signing.
* `pkg/mta` (`mta`) is the outbound engine: it owns the spool, the delivery
  loop, MX resolution, DKIM signing, retry scheduling, DSN bounces, webhook
  notifications, optional smarthost relaying, and Prometheus metrics.
* `pkg/smtp` (`smtp`) is the inbound listener: it speaks SMTP, parses the
  message, synthesizes an `*http.Request`, and runs a Caddy route against it.
  All policy (relaying, filtering, rejection) belongs to that route.
* `pkg/sendmail` (`sendmail`) is the HTTP front door for outbound mail: it
  accepts a POST, builds an envelope, and enqueues through the `mta` app.

`email.go` (package `caddyemail`) is the plugin root: it blank-imports the three
module packages so `xcaddy build` links them in.

Two independent directions of flow:

```
outbound   HTTP POST /sendmail  ─┐
           template {{ sendmail }} ─┴─▶ mta.Enqueue ─▶ spool/incoming
                                                          │  (tick)
                                                          ▼
                                    resolve MX (or relay) ─▶ SMTP to peer
                                                          │
                        delivered ── unlink        deferred ── defer + backoff
                        bounced   ── DSN           │
                                                     ▼
                                          notify_url webhook (fire and forget)

inbound    TCP :25/:587 ─▶ smtp session ─▶ parse ─▶ synth *http.Request ─▶ route
```

The `smtp` listener never touches the spool. The `mta` app never speaks the
inbound protocol. `sendmail` depends on `mta` only through the `shared.Enqueuer`
interface, resolved at provision time via `ctx.App("mta")`.

---

## 2. Shared Foundations (`pkg/shared`)

### 2.1 Spool layout

The spool is a directory with one subdirectory per state:

| State | Meaning |
|---|---|
| `incoming/` | Accepted, waiting to be picked up |
| `active/` | Claimed by the delivery loop, in flight |
| `deferred/` | Temporary failure, waiting for `next_at` |
| `bounce/` | Permanently failed, retained for `bounce_retention` |
| `corrupt/` | Unparseable `qf`, quarantined |

Each job is a pair of files named by a shared id:

* `df<id>` is the message body, verbatim, exactly as it will be sent.
* `qf<id>` is the control file: envelope, attempt count, and next-attempt time.

**`qf` is the commit marker.** A message is only considered accepted once its
`qf` exists, and every transition moves `df` before `qf` so that a crash never
leaves a committed `qf` without its body.

The id is 11 bytes (8 bytes big-endian `UnixNano`, 3 bytes of `crypto/rand`),
base32-encoded with no padding and lower-cased. If the entropy source fails, a
process-local counter is folded in so ids stay unique.

### 2.2 `qf` format

Line-oriented, one field per line, identified by its first byte:

```
V8
T<enqueued unix seconds>
N<attempts>
P<next-attempt unix seconds, 0 for none>
MD<last error>            (only when non-empty)
S<envelope sender>
R<recipient>              (repeated, one per recipient)
H?<key>: <value>          (repeated, one per envelope meta entry, sorted)
```

`parseQF` dispatches on the first byte and rejects any `V` line that is not the
current `SchemaVersion` (`V8`). Unknown line types are ignored, which is what
makes the format forward-extensible. Envelope meta (`H?`) is preserved across
deferrals so caller-supplied metadata survives retries.

### 2.3 Atomic writes

Every file that matters is written through `atomicWrite`: create a `.tmp` file
with mode `0600`, write, `fsync` the file, close, `rename` over the target, then
`fsync` the containing directory. The directory sync is what makes the rename
itself durable. Spool directories are created `0700`.

### 2.4 Spool operations

| Function | Effect |
|---|---|
| `Enqueue` | Writes `df` then `qf` into `incoming/`, returning the id |
| `CloneJob` | Writes a new `incoming/` job for a subset of recipients, sharing the body |
| `RewriteRecipients` | Replaces the `R` lines of an `incoming/` `qf` in place |
| `ScanEligible` | Lists `incoming/` jobs older than `settle` and past `next_at`, oldest first, capped at `limit` |
| `Claim` | Moves `df` then `qf` from `incoming/` to `active/` |
| `Unlink` | Removes both files from `active/` after delivery |
| `Defer` | Rewrites `qf` with new attempt state and moves `df` then `qf` to `deferred/` |
| `Bounce` | Moves `df` then `qf` from `active/` to `bounce/` |
| `RecoverActive` | Moves `active/` entries older than a cutoff back to `incoming/`, skipping jobs still in flight in this process |
| `ReconcileSpool` | Reunites a `qf`/`df` pair split by a crash, removes an orphan `df`, quarantines a bodyless `qf` |
| `SweepDeferred` | Moves `deferred/` jobs whose `next_at` has passed back to `incoming/` |
| `SpoolSize` | Total bytes under the spool, for quota accounting |
| `PruneBounce` | Deletes `bounce/` files older than a cutoff |

`ScanEligible` is the only reader that also quarantines: a `qf` that fails to
parse is moved to `corrupt/` rather than retried forever.

### 2.5 Message construction and validation

* `BuildSimple(from, to, subject, body)` writes the minimal RFC 5322
  `text/plain` message used by the template function's positional form.
* `BuildMessage(from, to, cc, replyTo, subject, body)` is the same with optional
  `Cc` and `Reply-To`. `Bcc` is deliberately not a parameter: it belongs to the
  envelope only and must never reach the headers.
* `SanitizeHeaderValue` replaces CR and LF with spaces, and every header write
  goes through it, so no caller can inject a header even if it skips validation.
* `ValidAddress` parses with `net/mail` and requires a non-empty local part with
  an `@`. `NormalizeAddress` returns the bare addr-spec, which sendmail and the
  `mta` use for the envelope so a display name (`Name <a@b>`) cannot reach an
  SMTP command or a DKIM `d=` tag. `ValidHeaderValue` rejects CR, LF, and NUL.

### 2.6 HMAC

`SignHMAC(secret, body)` returns `sha256=<hex>`; `VerifyHMAC` compares with
`hmac.Equal`. The `mta` webhook uses the former for the `MTA-Signature` header.

---

## 3. The `mta` App

### 3.1 Configuration

Global option `mta`. Every field is also a JSON field on the `MTA` struct.

| Option | Default | Notes |
|---|---|---|
| `hostname` | system hostname, else `localhost.localdomain` | Used in DSNs and the `MAILER-DAEMON@` sender |
| `spool_dir` | `/var/spool/caddy` | Created with all six state subdirectories |
| `settle_delay` | `1s` | Minimum age before a new job is eligible |
| `tick_interval` | `settle_delay/4`, clamped to `[10ms, 250ms]` | Delivery loop period |
| `max_batch` | `1000` | Jobs scanned per tick |
| `concurrency` | `50` | Global in-flight delivery limit |
| `per_mx_concurrency` | `2` | Connections per delivery target (per MX, or the relay) |
| `max_retries` | `5` | Attempts before a permanent bounce |
| `initial_backoff` | `5m` | First retry delay |
| `max_backoff` | `4h` | Backoff ceiling |
| `connect_timeout` | `15s` | Dial timeout, and the basis for active recovery |
| `data_timeout` | `30s` | Body transfer timeout |
| `command_timeout` | `5m` | Per-command deadline |
| `notify_url` | none | Webhook for delivery events |
| `notify_secret` | none | HMAC key for `MTA-Signature` |
| `mx_cache_ttl` | `5m` | MX cache lifetime |
| `require_tls` | `false` | Defer rather than deliver in cleartext |
| `relay` | none | `host[:port]` smarthost; overrides MX resolution |
| `max_spool_bytes` | `0` (unlimited) | Reject new mail above this |
| `bounce_retention` | `168h` | Retention for `bounce/` |
| `shutdown_timeout` | `30s` | Cap on draining in-flight deliveries |
| `dkim { selector domain private_key }` | none | RSA signing; `selector` and `private_key` required |

`Validate` enforces: `settle_delay >= 0`, `concurrency > 0`,
`per_mx_concurrency > 0`, `max_batch > 0`, `max_retries >= 0`,
`max_spool_bytes >= 0`, a non-empty host in `relay`, and a well-formed `http(s)`
`notify_url`. A `notify_url` without `notify_secret` (or the reverse) logs a
warning rather than failing.

### 3.2 Lifecycle

**Provision** creates the spool directories, the buffered notification channel
(1024 events), the HTTP client for webhooks (10s timeout), the MX cache and
per-MX semaphore maps, parses the DKIM private key (PKCS#8 or PKCS#1), and
registers metrics. Metrics registration is best-effort: a failure is logged and
does not fail startup.

**Start** takes an exclusive `flock` on `.caddy-email.lock` inside the spool, so
two Caddy processes cannot deliver from the same queue. `flock` is advisory and
released by the kernel on exit, so a crash leaves no stale lock; on non-Unix
platforms `lockSpool` is a no-op. It then seeds the spool-size counter, reconciles
`qf`/`df` pairs split by a crash, recovers stale `active/` entries, starts four
webhook workers when `notify_url` is set, and starts the delivery loop and the
janitor.

**Stop** closes the stop channel exactly once, waits up to `shutdown_timeout`
for in-flight work, and releases the lock. Timing out is logged, not fatal.

**The janitor** runs every 30s: it recomputes `SpoolSize` (the quota figure is
approximate between runs), reconciles split pairs, recovers stale `active/`
entries while skipping jobs still in flight, and prunes `bounce/` past
`bounce_retention`. Recovery runs here as well as at startup so a job claimed
moments before a crash, initially too recent to recover, gets a later chance.

### 3.3 The delivery tick

Each tick:

1. `SweepDeferred` moves due deferred jobs back to `incoming/`.
2. `ScanEligible` collects up to `max_batch` eligible jobs.
3. Unless a relay is configured, `splitMultiDomain` rewrites any job whose
   recipients span several domains into one job per domain. This is required
   because a multi-domain job would land in several MX groups and be delivered
   by concurrent goroutines, duplicating copies and racing on the spool files.
   With a relay, every job targets the same host, so there is nothing to split.
4. Each job is `Claim`ed into `active/`; a job that cannot be claimed is skipped
   for this tick.
5. Jobs are grouped by delivery target, and each group runs in its own
   goroutine, bounded by `concurrency` (global) and `per_mx_concurrency` (per
   target).

### 3.4 Delivery

`deliverOne` reads the body from `active/`, signs it if DKIM is configured, and
tries each host in preference order until one completes a connection and
greeting. If every host fails to connect, the job is deferred; once connected,
failures are per-message and retried on the next pass.

DKIM signs into a transient copy. The spooled `df` stays raw so that a retry is
re-signed from scratch instead of accumulating nested signatures.

`deliverSession` runs `MAIL FROM`, then `RCPT TO` for each recipient, collecting
the accepted and rejected sets. If no recipient is accepted the job is deferred.
`DATA` is bounded by `data_timeout`, after which the deadline returns to
`command_timeout` for the final reply.

On success the job is unlinked, a `delivered` event is emitted for the accepted
recipients, and any rejected recipients are re-enqueued as a new deferred job
that inherits the attempt count (see Partial delivery).

### 3.5 Retry and backoff

`failTemporary` increments the attempt count and, while attempts remain,
schedules the next attempt at `initial_backoff << (attempts-1)`, clamped to
`max_backoff`, plus up to 25% random jitter. The shift is capped at 20 so a large
`max_retries` cannot overflow into a negative duration. Past `max_retries` the
failure is promoted to permanent.

### 3.6 Bounces and DSNs

`failPermanent` moves the job to `bounce/` and notifies a bounce. A DSN is then
generated and queued back to the envelope sender unless `canBounce` says
otherwise: a null or unparseable sender, a job already marked as a DSN (via the
`dsn` meta key), or a `MAILER-DAEMON` local part all suppress the notification,
so bounces cannot loop.

The DSN is an RFC 3464-style `multipart/report` carrying a human-readable
`text/plain` part and a `message/delivery-status` part with
`Reporting-MTA`/`Final-Recipient`/`Action`/`Status`/`Diagnostic-Code` fields.

### 3.7 Partial delivery

When some recipients are accepted and others rejected, the accepted ones are
delivered and the job is unlinked. The rejected ones become a new job sharing the
same body, claimed and immediately deferred with the inherited attempt count, so
they resume the retry schedule rather than starting over. Once attempts are
exhausted they bounce.

### 3.8 MX resolution

`resolveTarget` consults an in-memory cache keyed by domain, then falls back to
`net.LookupMX` (held in a package variable so tests can stub DNS). Outcomes:

* One or more MX records: hosts sorted by preference, trailing dots stripped.
* A single root record (`MX 0 .`): the RFC 7505 null MX, meaning the domain
  accepts no mail. Such a job is bounced without a delivery attempt.
* No MX records, or NXDOMAIN for MX: fall back to the domain's A/AAAA record as
  an implicit MX.
* Any other DNS error: temporary, so the job is deferred.

`recipientDomain` lower-cases the part after the last `@`, which is how jobs are
grouped and keyed for per-target concurrency.

### 3.9 Relay (smarthost)

When `relay` is set to `host[:port]`, MX resolution is skipped entirely and every
job is grouped under a single target. The port defaults to 25. `per_mx_concurrency`
therefore limits connections to the smarthost as a whole, which is the knob for
matching a downstream server's limits. Opportunistic STARTTLS and `require_tls`
behave as they do for direct delivery, and DKIM, retries, bounces, and webhooks
are unchanged.

### 3.10 DKIM

`dkimSign` prepends a `DKIM-Signature` header using `rsa-sha256` with
`simple/simple` canonicalization. `bh=` is the SHA-256 hash of the canonicalized
body, and the RSA signature covers the listed headers
(`From:To:Subject:Date:MIME-Version:Content-Type`) in that order, followed by
the `DKIM-Signature` header itself with an empty `b=` value, as RFC 6376
section 3.7 requires, so the produced signature verifies. Signing is skipped
when no key is configured, or when neither the configured domain nor the
sender's domain is available. A configured domain that disagrees with the
sender's domain is logged as a warning.

### 3.11 Webhook events

Delivered, deferred, and bounced events are POSTed to `notify_url` as JSON, with
`MTA-Signature: sha256=<hmac>` when `notify_secret` is set. Delivery is
fire-and-forget: four workers drain a 1024-event buffer, a slow endpoint cannot
throttle delivery, and an event that cannot be buffered is dropped with a warning.
Errors are logged and forgotten; there is no retry, replay, or ordering
guarantee. When `notify_url` is unset, events are logged instead.

### 3.12 Metrics

Registered into Caddy's per-context registry at provision time, so they appear on
the admin `/metrics` endpoint alongside Caddy's own. Namespace `caddy_email`,
deliberately not `caddy`, to avoid colliding with Caddy core.

| Metric | Type | Labels |
|---|---|---|
| `caddy_email_mta_events_total` | counter | `event` (`delivered`, `deferred`, `bounced`) |
| `caddy_email_mta_enqueued_total` | counter | |
| `caddy_email_mta_notify_dropped_total` | counter | |
| `caddy_email_mta_spool_jobs` | gauge | `state` |
| `caddy_email_mta_spool_bytes` | gauge | |

The spool gauges are computed at scrape time from a single walk of the spool, so
they are exact rather than sampled; a scrape on a very large spool costs one
directory walk. Registration tolerates `AlreadyRegistered` so a reload or a second
instance does not fail.

---

## 4. The `smtp` App

### 4.1 Configuration

Global option `smtp`, repeatable per port: `smtp :25 { ... }` and
`smtp :587 { ... }` declare independent listeners.

| Option | Default | Notes |
|---|---|---|
| `hostname` | system hostname, else `localhost.localdomain` | Greeting and `EHLO` name |
| `tls` | `off` | `starttls` or `off`; anything else is rejected |
| `tls_cert_file` / `tls_key_file` | none | Both required when `tls starttls` |
| `max_message_size` | 25 MiB | `552` past this |
| `max_recipients` | 50 | `452` on the 51st `RCPT TO` |
| `max_connections` | 200 | Concurrent connections |
| `deliver_timeout` | 30s | Read/write deadline and idle cap |
| `route` | none | Caddy route the parsed message is handed to |

There are no port-specific defaults: every listener starts with `tls off`, no
authentication, and no relay policy.

### 4.2 Session

A session is a plain SMTP dialogue. `EHLO`/`HELO` records the client name;
`MAIL FROM:<addr>` sets the sender, and the null reverse-path `MAIL FROM:<>` is
accepted as a real (empty) sender, tracked separately from "no MAIL yet"; one or
more `RCPT TO:<addr>` set the recipients; `DATA` collects the body until a lone
`.` line, unescaping leading dots. `RSET` clears the transaction (including the
placeholders that expose it), `NOOP` is a no-op, `QUIT` ends the session, and an
unrecognized command gets `500`. `DATA` before `MAIL` or `RCPT` gets `503`.

Advertised extensions: `SIZE`, `PIPELINING`, `ENHANCEDSTATUSCODES`, `8BITMIME`,
and `STARTTLS` when configured. `AUTH` is never advertised: this is a receive-only
listener.

The read deadline is rearmed before every read, so an idle client is dropped but
a slow-but-active transfer is not. Individual lines are capped (8 KiB for a
command, 1 MiB for a body line), so an unterminated line cannot exhaust memory
before `max_message_size` is checked; an over-long command gets `500` and an
over-long body line gets `552`. When the body exceeds `max_message_size` the
listener answers `552` and drains the remainder of `DATA` so trailing body lines
are never misparsed as commands; a client that keeps streaming is disconnected.

`STARTTLS` replies `220`, wraps the connection with a TLS server handshake
(using Go's default minimum version, which is TLS 1.2), and swaps the reader and
writer. It is refused with `503` while a transaction is open or once TLS is
already active, and the handshake discards the pre-TLS session state (`HELO`
name and envelope) per RFC 3207 section 4.2.

### 4.3 Dispatch to the route

`dispatch` synthesizes an `*http.Request`: method `POST`, path `/`, an allowlist
of the message's headers copied in, the body after the header/body separator,
and envelope metadata as headers (`From`, `To`, `Client-Helo`, `Client-IP`,
`Smtp-TLS`). The allowlist covers standard envelope and content headers
(`From`, `Sender`, `Reply-To`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`,
`In-Reply-To`, `References`, `Return-Path`, `Received`, `Delivered-To`,
`MIME-Version`, `Content-*`, `Precedence`, `Priority`, `Importance`,
`Auto-Submitted`, `X-Mailer`, `User-Agent`) plus `List-*`, `ARC-*`, `X-Spam-*`,
and `X-Virus-*`; everything else is dropped, so a sender cannot inject
`Authorization`, `Cookie`, `Content-Length`, `X-Forwarded-For`, or any other
HTTP-sensitive header into a `reverse_proxy` route. A
Caddy replacer is attached carrying `{smtp.remote_ip}`, `{smtp.local_ip}`,
`{smtp.hostname}`, `{smtp.helo}`, `{smtp.from}`, `{smtp.rcpt}`, `{smtp.rcpts}`,
and `{smtp.tls}`.

With no `route` configured the message is accepted with `250`. Otherwise the
route runs under `deliver_timeout`, and its HTTP status is mapped back to SMTP:

| HTTP status | SMTP reply |
|---|---|
| none, or `2xx`/`3xx` | `250 2.0.0 OK` |
| `502`, `503`, `504` | `451 4.4.1 Backend unavailable` |
| other `4xx` | `451 4.4.1 Temporary failure` |
| anything else | `550 5.0.0 Rejected` |

That mapping is the whole point of the listener: returning a 4xx from the route
makes the remote MTA retry.

### 4.4 Metrics

`caddy_email_smtp_connections_total` (connections accepted) and
`caddy_email_smtp_messages_total` (messages accepted by the route, i.e. replied
`250`), registered the same way as the `mta` metrics.

---

## 5. `sendmail`

### 5.1 HTTP handler

Directive `sendmail`, ordered before `file_server`. Options: `from`,
`default_subject`, `max_body_size` (default 30 MB), and `allowed_from`.

`ServeHTTP` accepts `POST` only (`405` otherwise), rejects an oversized
`Content-Length` with `413`, caps the body with `http.MaxBytesReader` so a
chunked upload cannot slip past, parses the request, applies `allowed_from`
(`403` on a non-match), and enqueues. Success is `202` with
`{"queue_id": "..."}`; an enqueue failure is `503`.

`allowed_from` patterns match the envelope sender: an exact address, a bare
domain or `@domain` (any sender in that domain), or `*suffix`.

### 5.2 Request formats

Dispatched on `Content-Type`:

* `message/rfc822`: pass-through. The envelope comes from the `From`, `To`, `Cc`,
  and `Bcc` headers; the body is sent verbatim.
* `application/x-www-form-urlencoded` and `multipart/form-data`: the envelope and
  headers are built from POST fields (`from`, `to`, `cc`, `bcc`, `reply-to`,
  `subject`, `body`). Query parameters are never consulted, so a query string
  cannot set envelope fields or headers.
* empty or `text/*`: metadata in HTTP headers, body is the message. An allowlist
  of headers is copied into the message (`From`, `To`, `Cc`, `Reply-To`,
  `In-Reply-To`, `References`, `Message-ID`, `Subject`, `Date`, `MIME-Version`,
  `Content-Type`, `Content-Language`, `Organization`, `Precedence`, `Priority`,
  `Importance`, `List-*`, `Auto-Submitted`, `X-Mailer`, `User-Agent`), with
  `Bcc` and hop-by-hop headers excluded. `Date`, `MIME-Version`, `Content-Type`,
  `Subject`, and `From` are filled in when absent.
* anything else: `400`.

Every envelope address is validated, so a bad address fails the request rather
than reaching the wire. `Bcc` recipients join the envelope but never the headers.

### 5.3 Template function

`http.handlers.templates.functions.sendmail` adds a `sendmail` function to the
`templates` handler. It accepts either a single dict
(`from`, `to`, `cc`, `bcc`, `subject`, `body`, `reply_to`/`reply-to`), or
positional arguments `(to, subject, body)` or `(from, to, subject, body)`. It
enqueues with a background context and returns the queue id. With `soft_fail` an
enqueue error is logged and returns an empty string instead of failing the
template.

### 5.4 Metrics

`caddy_email_sendmail_enqueued_total`.

---

## 6. Security Invariants

* Header injection: every header value passes through `SanitizeHeaderValue`, and
  addresses are validated with `net/mail`, so CR/LF cannot escape into a header
  or an SMTP command.
* Envelope hygiene: `Bcc` is never written into headers; query parameters never
  set envelope fields.
* Inbound header isolation: only allowlisted message headers reach the route's
  synthesized request, so a sender cannot set `Authorization`, `Cookie`,
  `Content-Length`, `X-Forwarded-For`, or other HTTP-level headers.
* Spool integrity: files are `0600` and directories `0700`; every write is
  fsync'd and renamed; the queue is single-writer via `flock`.
* Webhook authenticity: payloads are HMAC-SHA256 signed when a secret is set, and
  compared in constant time.
* Resource bounds: the SMTP listener bounds concurrent connections and message
  size, and bounds idle time with a rearmed read deadline.

---

## 7. Not yet built

Deliberately unimplemented. Defects and hardening work live in `BACKLOG.md`.

* **SMTP `AUTH` and submission.** The listener is receive-only and never
  advertises `AUTH`; there is no credential store. Admission is a route decision.
* **Relay policy on the listener.** No `permit_mynetworks`-style control; use a
  `remote_ip` matcher in the route.
* **Relay authentication.** `relay` sends unauthenticated.
* **Per-domain relaying.** `relay` is global; there is no per-recipient routing
  table.
* **MTA-STS / DANE.** `require_tls` only enforces opportunistic STARTTLS.
* **DKIM canonicalization choices.** Only `simple/simple`; no `relaxed`.
* **Attachments in sendmail.** Pre-build MIME and POST as `message/rfc822`.
* **Queue inspection API.** Read the files in `spool_dir`.
* **Admin hold/resume.** No way to park a job: there is no `hold/` state
  and no admin API.
* **`Received:` tracing.** The MTA does not prepend a `Received` header.
* **IMAP / POP3.** This is an MTA.
