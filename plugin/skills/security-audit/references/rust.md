# Rust checklist

In addition to [core.md](core.md). Rust prevents most memory bugs, so look at `unsafe`, panics (DoS), logic, crypto use, and the same injection/authorization issues as any language. Items marked 🧠 need reasoning that the scanner can't do.

## Memory safety
- [ ] `unsafe` blocks / fns / impls [TAI-RS-001]. 🧠 For each one: is there a `// SAFETY:` comment, and is it true? Check raw pointer lifetimes, `from_raw_parts` lengths, `transmute`, `get_unchecked`, `set_len` before init, `Send`/`Sync` impls on types with interior raw pointers.
- [ ] 🧠 FFI boundaries: C strings without NUL checks, buffers sized by the foreign side, callbacks that can unwind across FFI (undefined behaviour).
- [ ] 🧠 Suggest `cargo miri test` for crates with `unsafe`, and `#![forbid(unsafe_code)]` where none is needed.

## Panics = denial of service
- [ ] `.unwrap()` / `.expect()` on parsing untrusted input [TAI-RS-002]. 🧠 Also: slice indexing `buf[i]` with attacker-controlled `i`, integer overflow (wraps in release, panics in debug), `RefCell` double borrow, division by user-supplied zero.
- [ ] 🧠 A panic in an async task or request handler: does the server recover, or does one request kill the process / poison a `Mutex`?
- [ ] 🧠 Unbounded allocation from input: `Vec::with_capacity(len_from_header)`, reading whole bodies without a limit (`axum` `DefaultBodyLimit`, `actix` `PayloadConfig`).

## Injection & filesystem
- [ ] `Command::new("sh"|"cmd")` with `-c` and formatted strings [TAI-RS-004]. Call the binary directly with `.args()`.
- [ ] SQL built with `format!` [TAI-CORE-010]. Use `sqlx::query!` / `.bind()`, diesel query builder. 🧠 `sqlx::query(&format!(...))` is still injectable.
- [ ] 🧠 `Path::join(user_input)`: an absolute input *replaces* the base path. Canonicalize and check `starts_with(base)`. Reject `..` components.
- [ ] 🧠 Archive extraction (`zip`, `tar` crates) without `enclosed_name()` / path checks → zip slip.

## Crypto
- [ ] Hardcoded keys/nonces [TAI-RS-005]. 🧠 AES-GCM / ChaCha20-Poly1305 nonce **must** be unique per key. Random 96-bit from `OsRng`, or a counter that is never reused.
- [ ] Non-CSPRNG / seeded RNG for secrets [TAI-RS-003]. `OsRng` and `thread_rng()` are fine. `SmallRng`, `seed_from_u64`, `fastrand` are not.
- [ ] 🧠 Password hashing with `argon2` (Argon2id) / `scrypt` / `bcrypt`, not `sha2` alone.
- [ ] 🧠 Secrets wrapped in `zeroize::Zeroizing` / `secrecy::Secret` so they're wiped on drop and not printed by `Debug`. Check `#[derive(Debug)]` on structs holding keys or passwords.
- [ ] Comparisons of MACs/tokens via `subtle::ConstantTimeEq` [TAI-CORE-011].
- [ ] TLS: `danger_accept_invalid_certs(true)` / custom `ServerCertVerifier` that accepts everything [TAI-CORE-008].

## Web (axum / actix / rocket / warp)
- [ ] 🧠 Auth implemented as an extractor or middleware that every protected route actually uses. Look for routes added outside the protected `Router`/scope.
- [ ] 🧠 Ownership checks on resource IDs (IDOR). `Path<Uuid>` doesn't make an ID unguessable *and* authorized.
- [ ] 🧠 `serde` structs for input with fields like `is_admin`, `role`, `user_id` → mass assignment. Use `#[serde(deny_unknown_fields)]` and separate input DTOs.
- [ ] 🧠 `tower_http::cors::CorsLayer::permissive()` / `very_permissive()` / `Any` with credentials.
- [ ] 🧠 Errors returned to clients with `{:?}` of internal errors (leaks paths, SQL).

## Supply chain
- [ ] 🧠 `Cargo.lock` committed for binaries; `build.rs` / proc-macros in unfamiliar crates run code at build time; recommend `cargo audit` and `cargo deny`.
- [ ] 🧠 Secrets or keys logged via `tracing` spans/fields [TAI-CORE-013].
