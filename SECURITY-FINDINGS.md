# Security findings & remediation — free-claude-code-secure

Scope: authorized defensive review of this hardened fork (KurtLehnardt/free-claude-code-secure).
Two independent reviews (DevSecOps + white-hat) plus an external-touchpoint audit. Severity per
CVSS-ish judgment. Status reflects the remediation pass tracked in this repo's history.

> Honesty notes: reviews were static + active code analysis; the live server was not run
> (`uv` unavailable in the review environment). `uv lock` and the full CI/test suite must be run
> before relying on the dependency and CI changes. This repo is private and not independently audited.

## Confirmed findings

| # | Sev | Finding | Location | Status |
|---|-----|---------|----------|--------|
| 1 | High | Proxy binds `0.0.0.0` with auth OFF by default; default token is public `freecc` → unauthenticated off-host use of your provider credentials, web tools, `/stop`. | `config/settings.py`, `api/dependencies.py` | Remediated: loopback default, auth-on, generated token, exposure fail-safe, TrustedHost |
| 2 | High | Telegram inbound authorization is fail-OPEN when `ALLOWED_TELEGRAM_USER_ID` unset → any Telegram user drives the managed agent subprocess. | `messaging/platforms/telegram_inbound.py` | Remediated: fail-closed (mirrors Discord) |
| 3 | High | Vulnerable transitive deps: starlette 0.52.1, python-multipart 0.0.22, urllib3, cryptography, idna. | `pyproject.toml` / `uv.lock` | Remediated: CVE floors added (needs `uv lock`) |
| 4 | Med | Admin GET routes reachable via DNS-rebinding (no Host-header allowlist; `_origin_is_local(None)=True`) → config/model-catalog/home-path disclosure. | `api/admin_routes.py` | Remediated: Host-header allowlist |
| 5 | Med | No request-body size cap → memory/CPU DoS. | `api/app.py` / `routes.py` | Remediated: body-size limit middleware |
| 6 | Med | npm installs (cline unpinned; dsh no integrity) bypass the checksum guarantee. | `scripts/install.sh` | Remediated: `npm pack` + fail-closed manifest verify; exact version pins |
| 7 | Med | Admin loopback gate spoofable via `X-Forwarded-For` if deployed with `FORWARDED_ALLOW_IPS=*`. | `api/commands.py` | Remediated: XFF not trusted for loopback decision |
| 8 | Med | No SAST / dependency-audit / secret-scan in CI. | `.github/workflows`, `scripts/ci.sh` | Remediated: Ruff `S`, pip-audit (`deps-audit`), gitleaks (`secrets-scan`) |
| 9 | Low | `~/.fcc` + `server.log` created with default umask. | `config/paths.py` | Remediated: 0700/0600 |
| 10 | Low | Weak default token; NAT64 loopback literal (`64:ff9b::/96`) accepted by SSRF guard. | `api/web_tools/egress.py` | Remediated (token + NAT64); domain-regex backtracking noted |

## Checked — defenses that HOLD (no change needed)
- SSRF guard blocks decimal/octal/hex IPs, IPv4-mapped IPv6, `0.0.0.0`, `::1`, link-local
  (`169.254.169.254`), private/CGNAT; DNS-rebind TOCTOU closed by a pinned resolver; per-hop redirect
  re-validation; scheme allowlist. (`api/web_tools/egress.py`, `outbound.py`)
- No `eval`/`exec`/`pickle`/`yaml.load`/`os.system`/`shell=True`; subprocess uses argv lists.
- `secrets.compare_digest` for token comparison. Session persistence: fixed path + mkstemp + atomic
  replace (no traversal). macOS `.app`/symlink install is owner- and symlink-checked.
- Upstream provider URL is config-only (not request-driven); provider API key sent only to the
  configured host; no incoming client headers forwarded upstream.
- No telemetry / analytics / phone-home anywhere in the source.

## External touchpoint inventory
- Install path: 7 vendor installer scripts + uv + RTK + free-claude-code — all checksum/commit pinned
  in `install.sh`. npm (cline/dsh) now pack-verified. **`install.ps1` vendor-script / `main.zip` / uv
  paths remain UNHARDENED (Windows gap).**
- Runtime: ~42 LLM provider hosts (config-only, receive your keys; egress-allowlisted in the
  container), provider OAuth (auth.openai.com, chatgpt.com, googleapis), messaging
  (api.telegram.org, Discord), `web_search` (lite.duckduckgo.com), `web_fetch` (arbitrary, SSRF-
  guarded), tiktoken BPE (openaipublic.blob…, cache-warmed in Docker), optional voice (HuggingFace,
  NVIDIA riva).

## Open / recommended (not yet done)
- **`install.ps1` full rewrite** to match `install.sh` (checksum manifest gating for vendor scripts,
  `main.zip` → pinned commit, pinned uv). Largest residual risk.
- Digest-pin container base images before production.
- Run `uv lock`; run `./scripts/ci.sh` + full pytest; enable branch-protection required checks for
  `deps-audit` and `secrets-scan`.
- Tier-2 scanners (hadolint/trivy/actionlint) — recommended, not yet wired.
