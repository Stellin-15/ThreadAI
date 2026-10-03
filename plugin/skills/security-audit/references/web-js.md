# JavaScript / TypeScript / web checklist

In addition to [core.md](core.md). Items marked 🧠 need reasoning that the scanner can't do.

## Browser / XSS
- [ ] DOM sinks fed by user data: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` [TAI-JS-001]. Fix: `textContent`, DOM APIs, or `DOMPurify.sanitize`.
- [ ] React `dangerouslySetInnerHTML` [TAI-JS-002]; 🧠 `href={userUrl}` allows `javascript:` URLs. Validate the scheme is `http(s):`. Vue `v-html`, Angular `bypassSecurityTrust*`, Svelte `{@html}`.
- [ ] 🧠 DOM XSS sources: `location.hash`, `location.search`, `document.referrer`, `postMessage` data (check `event.origin`!), `localStorage` values written by other pages.
- [ ] 🧠 Tokens in `localStorage` are readable by any XSS. Prefer `HttpOnly` cookies for sessions.
- [ ] 🧠 `target="_blank"` to untrusted URLs without `rel="noopener"` (older browsers).
- [ ] 🧠 CSP present and without `unsafe-inline` / `unsafe-eval` where possible.

## Node / Express / Fastify / Koa
- [ ] `child_process.exec`/`execSync` with interpolated input [TAI-JS-003]. Fix: `execFile`/`spawn` with an array, `shell: false`.
- [ ] `new Function`, string `setTimeout`, `vm.runInNewContext` with user code (the `vm` module is **not** a sandbox) [TAI-JS-004].
- [ ] 🧠 **Prototype pollution:** recursive merge/`set(obj, userPath, value)`/`lodash.merge`/`Object.assign` from JSON with `__proto__` or `constructor.prototype` keys. Fix: `Object.create(null)`, key allowlists, `structuredClone`, updated libraries.
- [ ] NoSQL injection: `find(req.body)` or `{ password: req.body.password }` where the value can be an object such as `{"$ne": null}` [TAI-JS-010]. Fix: cast to `String()`, validate with zod/joi, `express-mongo-sanitize`.
- [ ] 🧠 `res.sendFile` / `fs.readFile` / `path.join(base, req.params.x)` → path traversal. Use `path.resolve` and check `startsWith(base + path.sep)`.
- [ ] Open redirect `res.redirect(req.query.next)` [TAI-JS-008].
- [ ] SSRF: `fetch`/`axios`/`got` with request-controlled URLs [TAI-JS-009].
- [ ] 🧠 `express.json()` / body-parser limits, upload limits (`multer` `limits`).
- [ ] 🧠 `helmet()` or equivalent headers; `app.disable('x-powered-by')`.
- [ ] 🧠 `cors({ origin: true, credentials: true })` or reflecting `req.headers.origin` [TAI-JS-006].
- [ ] 🧠 Error handler returns `err.stack` to clients in production.
- [ ] 🧠 `RegExp(userInput)` → ReDoS/injection. Escape it or avoid building regexes from input.

## Auth libraries
- [ ] `jwt.decode` used for auth decisions; `algorithms` not pinned [TAI-JS-005]; hardcoded secret [TAI-JS-011].
- [ ] 🧠 `bcrypt`/`argon2` used for passwords, not `crypto.createHash` [TAI-CORE-006].
- [ ] `Math.random` for tokens/IDs [TAI-JS-007] → `crypto.randomBytes` / `crypto.randomUUID`.
- [ ] 🧠 `express-session` / `cookie-session`: `secret` from env; `cookie: { httpOnly, secure, sameSite }`.
- [ ] 🧠 Passport/NextAuth callbacks that trust the email from an unverified provider (account takeover).

## Next.js / full-stack frameworks
- [ ] 🧠 Server Actions and API routes do their **own** auth check. Middleware-only protection can be bypassed, and actions are public endpoints.
- [ ] 🧠 Secrets only in server code; nothing secret in `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*`.
- [ ] 🧠 `getServerSideProps` / RSC passing full DB objects into client props (leaks hidden fields).
- [ ] 🧠 Image/URL proxy endpoints (`/_next/image` remotePatterns too broad, custom proxies) → SSRF.

## TypeScript specifics
- [ ] 🧠 `as` casts or `any` on request data hide missing validation. Types are not runtime checks, so validate with zod/valibot at the boundary.

## Dependencies
- [ ] 🧠 `package-lock.json` / `pnpm-lock.yaml` committed; `postinstall` scripts in unfamiliar deps; recommend `npm audit --omit=dev`.
