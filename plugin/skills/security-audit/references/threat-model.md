# Threat modelling for an audit

Short, practical version: enough structure that nothing obvious is skipped, without writing a thesis.

## 1. Draw the system in words

Write 3–8 lines like:

```
browser --HTTPS--> Express API (/api/*) --SQL--> Postgres
                     |--> S3 (user uploads)
                     |--> Stripe webhook (inbound, /hooks/stripe)
admin panel (/admin/*) — same app, role check in middleware
```

Mark each arrow that crosses a **trust boundary**: wherever data from a less-trusted side reaches a more-trusted one.

## 2. STRIDE per entry point

For each entry point (route, CLI arg, file parser, webhook, queue consumer), ask the six questions. Skip the ones that clearly don't apply.

| Letter | Threat | Question to ask | Typical finding |
|---|---|---|---|
| **S** | Spoofing | Can I pretend to be someone else? | missing/weak auth, JWT not verified, webhook signature not checked, session fixation |
| **T** | Tampering | Can I change data or code I shouldn't? | SQL/NoSQL/command injection, mass assignment, prototype pollution, unsigned cookies |
| **R** | Repudiation | Could I do damage with no trace? | no audit log for admin/money actions, logs writable by the app user |
| **I** | Information disclosure | Can I read what I shouldn't? | IDOR, verbose errors/stack traces, secrets in repo/logs, path traversal, SSRF to metadata |
| **D** | Denial of service | Can I knock it over cheaply? | unbounded upload/body size, ReDoS, panic on bad input, no rate limit on expensive endpoints, zip/XML bombs |
| **E** | Elevation of privilege | Can I become admin / run code? | missing authz on admin routes, role taken from request body, deserialization RCE, `eval` |

## 3. Trace source → sink

For every untrusted **source**, follow the value until it hits a dangerous **sink** or is safely validated.

**Sources:** request params/query/body/headers/cookies, uploaded files and filenames, URL path segments, env vars set by others, CLI args, message-queue payloads, third-party API/webhook bodies, DB rows that users wrote earlier (stored attacks).

**Sinks:**
- **Execution:** `eval`, `exec`, `new Function`, `pickle.loads`, `yaml.load`, template compilation, `child_process`, `subprocess`, `Command::new("sh")`
- **Queries:** SQL strings, Mongo filters, LDAP, XPath, GraphQL built by concatenation
- **Filesystem:** `open`/`readFile`/`send_file` with user paths, archive extraction (zip slip), upload save paths
- **Network:** `fetch`/`requests`/`reqwest` to user URLs (SSRF), redirects (open redirect)
- **Output:** HTML responses, `innerHTML`, `dangerouslySetInnerHTML`, `|safe`, log lines (log injection), response headers (header injection)
- **Authorization decisions:** any `if user.role ==`, ownership check, feature flag read from the request

For each source→sink pair, record: **validated? encoded for the sink? authorized?** A finding is a pair where the answer is no and the attacker can reach the source.

## 4. Things a line-by-line scanner can't see — always check these yourself

- **Broken access control (OWASP #1).** For every route that reads or changes a resource by ID: does it check that *this* user owns it or may act on it (IDOR)? Are admin routes protected server-side, not just hidden in the UI?
- **Authentication flows.** Password reset tokens: random, single-use, expiring, not leaked in the Referer? Login: rate-limited? Response doesn't reveal whether the user exists? Session cookie `HttpOnly`, `Secure`, `SameSite`? Session rotated on login?
- **Mass assignment.** `User.update(req.body)` or `Model(**request.json)` lets an attacker set `is_admin`, `balance` or `owner_id`.
- **Business logic.** Negative quantities, coupon reuse, skipping steps in a multi-step flow, changing the price client-side, race conditions on balance and inventory (check-then-act without a lock or transaction).
- **Multi-line injection.** A query built across several lines, or a shell command assembled in a variable before the call.
- **Insecure defaults & fail-open.** `except: pass` around auth, `if (!config.authEnabled) next()`, missing CSRF on cookie-auth forms, CORS reflecting any origin.
- **Secrets lifecycle.** Where do secrets come from? Are they in Docker images, CI logs, frontend bundles (`NEXT_PUBLIC_*`, `VITE_*`), mobile apps?
- **AI/LLM features.** User text passed into an LLM prompt that also has tools or secrets (prompt injection → data exfiltration); model output passed to `eval`, SQL, shell or HTML.

## 5. Rate it

Severity = **how easy** (unauthenticated? one request?) × **how bad** (RCE, all data, one user's data, cosmetic). Write the attack as the concrete sequence of requests or inputs an attacker sends. If you can't write that sequence, you're not sure, so lower the confidence.
