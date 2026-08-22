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

## Remediated after initial pass
- **`install.ps1`** brought to full parity with `install.sh` (checksum manifest gating for all Windows
  vendor scripts + pinned uv artifact + OpenCode + RTK, `main.zip` → pinned commit, `-AllowUnpinned`
  / `-RefreshChecksums`, TLS 1.2 enforcement). Windows smoke test still required (unrun — no pwsh).
- **CI is now GREEN** (was red on stale tests). `starlette>=1.6.0` needed `httpx2` (starlette 1.x
  TestClient) to avoid a fatal deprecation under `filterwarnings=error`; added it. Installer/CI tests
  rewritten for hardened behavior + 5 new security tests. Verified on Python 3.14 via uv:
  `ruff format --check`, `ruff check`, `ty`, full `pytest` (3651 passed), and e2e (9 passed) all green.
  (`deps-audit`/pip-audit couldn't bootstrap locally — ensurepip SIGABRT — but resolved versions are
  the patched CVE floors; runs on GitHub CI.)

## Second-pass full review (opus) — findings & remediation
0 Critical, 0 High, 1 Medium, 3 Low, 5 Info. Core remediations re-traced end-to-end and hold.
- **Medium #1 (FIXED):** exposure fail-safe was start-time-only; bypassable via the `fcc-desktop`
  path and admin-triggered in-process restarts. Now enforced inside `ServerSupervisor._run_once`, so
  every bind/rebind runs the guard. New tests cover restart-into-unsafe and the desktop path.
- **Low #2 (FIXED):** over-cap chunked body returned 500; `BodySizeLimitMiddleware` now emits the
  413 JSON directly (with response-started tracking to avoid double-send). New parametrized test.
- **Low #3 (FIXED):** admin local-provider probe now routed through the egress guard (loopback-only
  allowance so local model servers stay probeable; metadata/LAN blocked). New tests.
- **Low #4 (FIXED):** SSRF guard's IPv4-embedding detection broadened to custom-prefix NAT64 + Teredo.
- **Info #5 (FIXED):** dead `ensure_config_dir` wired into token-path creation (0700 dir, DRY).
- **Info #8 (FIXED):** stale Dockerfile HOST comments corrected (settings default is now 127.0.0.1;
  the image intentionally sets HOST=0.0.0.0 for container networking, safe via auth-on + loopback
  publish + the exposure fail-safe).
- **Info #9 (FIXED):** added bracketed `[::1]` to the TrustedHost loopback allowlist.
- **Info #6/#7 (ACCEPTED, documented):** the managed coding-agent subprocess runs with
  `--dangerously-skip-permissions` (inherent to running autonomous coding agents) — the messaging
  inbound allowlists (Telegram + Discord, both fail-closed) are the RCE barrier. `"testserver"` in
  the Host allowlist is not internet-routable.

## Open / follow-ups (lower priority)
- **Provider-test SSRF (new, Low):** `services.admin.test_provider` (`runtime/application.py:230`)
  probes the configured provider base_url via the provider client abstraction (not a raw call), so it
  wasn't covered by the Low #3 fix. Same class (operator-config, loopback-admin-gated). Guarding it
  means threading egress validation into the provider client layer — deferred.
- **Admin apply-time persistence:** an admin can still *persist* an unsafe HOST/auth config; it can no
  longer take effect on any bind (Medium #1 fix), but rejecting it at apply-time is a further hardening.
- **Admin probe not DNS-pinned:** validated then fetched via httpx (narrow TOCTOU; operator-config,
  status-only) — accepted vs the Low severity.
- Digest-pin container base images before production; enable branch-protection required checks for
  `deps-audit`/`secrets-scan`; Tier-2 scanners (hadolint/trivy/actionlint); Windows `install.ps1`
  smoke test.
