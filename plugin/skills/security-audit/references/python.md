# Python checklist

In addition to [core.md](core.md). Items marked 🧠 need reasoning that the scanner can't do.

## Code execution & deserialization
- [ ] `pickle`/`dill`/`joblib`/`shelve` loads of untrusted bytes [TAI-PY-001]. 🧠 Includes cached ML models and files downloaded from the internet. `torch.load` without `weights_only=True` is pickle too.
- [ ] `yaml.load` without `SafeLoader` [TAI-PY-002].
- [ ] `eval` / `exec` / `compile` on input [TAI-CORE-007, TAI-PY-007]. Use `ast.literal_eval` for literals.
- [ ] `subprocess(..., shell=True)` [TAI-PY-003], `os.system`/`os.popen` [TAI-PY-004]. 🧠 Also multi-line calls where `shell=True` is on a different line from the command.
- [ ] 🧠 `importlib.import_module(user_input)` / `getattr(module, user_input)` used as dispatch → call arbitrary functions. Use an explicit dict.

## Web: Django
- [ ] `DEBUG = True` [TAI-CORE-009]; 🧠 `ALLOWED_HOSTS = ['*']`; `SECRET_KEY` from env [TAI-CORE-003].
- [ ] 🧠 `.raw()`, `.extra()`, `RawSQL`, `cursor.execute(f"...")` [TAI-CORE-010].
- [ ] `mark_safe`, `|safe`, `{% autoescape off %}` with user data [TAI-PY-005].
- [ ] 🧠 `@csrf_exempt` on cookie-authenticated views.
- [ ] 🧠 Querysets not filtered by `request.user` → IDOR (`Invoice.objects.get(pk=pk)`).
- [ ] 🧠 `ModelForm` with `fields = '__all__'` or DRF serializers with writable `is_staff`/`owner` → mass assignment.
- [ ] 🧠 `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS` set in production.

## Web: Flask / FastAPI
- [ ] `app.run(debug=True)` [TAI-CORE-009]. The Werkzeug debugger gives a remote Python shell.
- [ ] 🧠 `render_template_string(user_input)` → SSTI → RCE (`{{ cycler.__init__.__globals__.os.popen('id').read() }}`).
- [ ] `Markup(...)` / `autoescape=False` with user data [TAI-PY-005].
- [ ] 🧠 `send_file(request.args['f'])` / `open(os.path.join(UPLOAD, name))` → path traversal. Use `werkzeug.utils.secure_filename` + `safe_join`.
- [ ] 🧠 `SECRET_KEY` hardcoded → forged session cookies [TAI-CORE-003].
- [ ] 🧠 FastAPI: endpoints missing `Depends(get_current_user)`; Pydantic models used for both input and output (leak `hashed_password`). Use separate response models.
- [ ] 🧠 `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.

## Network & parsing
- [ ] `requests(..., verify=False)` [TAI-CORE-008]; 🧠 no `timeout=` → hung workers (DoS).
- [ ] 🧠 `requests.get(user_url)` → SSRF. Validate the host and resolved IP, and disable redirects.
- [ ] stdlib XML parsers on untrusted XML [TAI-PY-010] → `defusedxml`.
- [ ] 🧠 `tarfile.extractall` / `zipfile.extractall` without member path checks → zip slip. On Python 3.12+ use `filter="data"`.
- [ ] `tempfile.mktemp` [TAI-PY-008].

## Crypto & auth
- [ ] `random` for secrets [TAI-PY-006] → `secrets`.
- [ ] `hashlib.md5/sha1/sha256(password)` [TAI-CORE-006]. Use `argon2-cffi`, `bcrypt` or `hashlib.scrypt`.
- [ ] `==` on tokens/HMACs [TAI-CORE-011] → `hmac.compare_digest`.
- [ ] PyJWT without verification or with `none` [TAI-PY-009]. 🧠 `algorithms=` must always be passed.
- [ ] `assert` for permission checks [TAI-PY-011].

## Misc
- [ ] 🧠 `except Exception: pass` around auth/permission logic (fail open).
- [ ] 🧠 `os.environ.get("SECRET", "default-secret")`: a hardcoded fallback is a hardcoded secret.
- [ ] 🧠 `logging` of `request.json` / headers (captures passwords, tokens).
- [ ] 🧠 Dependencies pinned (`requirements.txt` with versions / a lock file); recommend `pip-audit`.
