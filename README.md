<div align="center">

<h1>
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="assets/free-claude-code-wordmark-light.svg">
    <img src="assets/free-claude-code-wordmark-dark.svg" alt="Free Claude Code" width="610">
  </picture>
</h1>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python 3.14](https://img.shields.io/badge/python-3.14-3776ab.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json&style=for-the-badge)](https://github.com/astral-sh/uv)
[![Testing: Pytest](https://img.shields.io/badge/Testing-Pytest-00c0ff.svg?style=for-the-badge)](https://github.com/Alishahryar1/free-claude-code/actions/workflows/tests.yml)
[![Type checking: Ty](https://img.shields.io/badge/type%20checking-ty-ffcc00.svg?style=for-the-badge)](https://pypi.org/project/ty/)
[![Code style: Ruff](https://img.shields.io/badge/code%20formatting-ruff-f5a623.svg?style=for-the-badge)](https://github.com/astral-sh/ruff)
[![Logging: Loguru](https://img.shields.io/badge/logging-loguru-4ecdc4.svg?style=for-the-badge)](https://github.com/Delgan/loguru)

[Quick Start](#quick-start) · [Providers](#choose-a-provider) · [Clients](#connect-your-client) · [Integrations](#optional-integrations) · [Manage](#manage-your-installation)

</div>

<p align="center">
  <em>Independent open-source project. Not affiliated with or endorsed by Anthropic. Claude and Claude Code are trademarks of Anthropic.</em>
</p>

> **This is a security-hardened fork.** It adds checksum-verified installation, a
> pinned git-commit supply chain, an isolated/egress-filtered Docker deployment,
> and a heuristic source audit script on top of upstream free-claude-code. See
> [Security](#security) for what these controls do and their honest limitations
> before relying on them.

## Recommended free providers

Free Claude Code routes your coding agent to whichever provider you configure. These
cloud providers offer **permanent free tiers or free models** and are supported out of
the box — pick one, grab an API key, set it (e.g. `GROQ_API_KEY`) and a `MODEL`:

- **[Groq](https://console.groq.com/keys)** — generous free tier with rate limits; no credit card required.
- **[SambaNova](https://cloud.sambanova.ai/apis)** — free tier for developers on SambaNova Cloud.
- **[Cerebras](https://cloud.cerebras.ai)** — free trial tier for developer inference.
- **[OpenRouter](https://openrouter.ai/keys)** — hosts specific models at zero token cost (look for the `:free` suffix).
- **[SiliconFlow](https://cloud.siliconflow.com/account/ak)** — specific models billed at zero cost within rate limits.
- **[Gemini — Google AI Studio](https://aistudio.google.com/apikey)** — free, rate-limited tier.
- **[Mistral & Mistral Codestral](https://console.mistral.ai/)** — La Plateforme offers free-tier API endpoints.
- **[Hugging Face](https://huggingface.co/settings/tokens)** — the Serverless Inference API is free for many open-source models.
- **[Cloudflare Workers AI](https://dash.cloudflare.com/profile/api-tokens)** — includes a free daily usage quota.
- **[Cohere](https://dashboard.cohere.com/api-keys)** — free, rate-limited developer tier for non-production use.

> **Tip:** free tiers have rate and payload limits. To drive a full coding agent (which
> sends a large system prompt), prefer a **large-context** model — e.g. NVIDIA NIM,
> Gemini, or an OpenRouter `:free` model with a big context window — since small-context
> free models can reject the request as too large. See [Choose a provider](#choose-a-provider).

## Security

This is a fork of upstream free-claude-code focused on hardening how the
project is **distributed and executed**, not a rewrite of its proxy logic.
Two remediation passes (tracked in [`SECURITY-FINDINGS.md`](SECURITY-FINDINGS.md))
address concrete risks across the whole surface: an install script piped from
the internet into `sh`/PowerShell with no integrity check, an unpinned
software supply chain (`main.zip`, rolling vendor installers, floating base
images), a local LLM proxy that holds provider API keys and routes model
traffic, an admin UI and `web_fetch` tool reachable from a browser or model
output, a messaging bridge that can drive an autonomous coding agent, and
outdated transitive dependencies with known CVEs — each a real target if the
install path, the running process, or an inbound message is tampered with or
over-exposed. None of this is a claim that the project is "secure,"
"unhackable," or has been independently audited or certified — see
[Caveats and limitations](#caveats-and-limitations) below for what is
deliberately still unverified or out of scope.

### Hardened installers

Both `scripts/install.sh` and `scripts/install.ps1` verify every downloaded
installer script or release artifact (Claude Code, Codex, Pi, OpenCode,
Hermes, Grok Build, Muse Code installers; the pinned `uv` release archive; the
RTK release archive) against a SHA256 in
[`scripts/install.checksums`](scripts/install.checksums) **before** it is
executed or extracted. The two scripts share one manifest and the same
fail-closed model, so Windows installs get the same guarantees as macOS/Linux.

- **Fail-closed by default.** If a component's manifest entry is missing or
  still the literal placeholder `REPLACE_ME`, the installer refuses to run
  that component rather than executing it unverified.
- **Populate hashes with trust-on-first-use.** Run the refresh mode on each
  platform you install on, review the printed hashes against a trusted
  source (e.g. the vendor's release page), then paste the reviewed lines into
  the manifest yourself — the installer never edits the manifest or executes
  anything in this mode:

  ```bash
  scripts/install.sh --refresh-checksums
  ```

  ```powershell
  scripts\install.ps1 -RefreshChecksums
  ```

- **Explicit escape hatch, not a default.** `--allow-unpinned` /
  `-AllowUnpinned` disables verification for components still unpinned and
  prints a warning banner; it is opt-in and intended for cases where you've
  already made a trust decision another way.
- **npm-distributed tools are pack-verified, not just pinned.** Cline and
  DeepSeek Harness (`fcc-cline`, `fcc-dsh`) are pinned to an exact version
  (never a floating `latest`) and installed via `npm pack` into a verified
  tarball rather than a bare `npm install -g <name>@<version>`.
- **RTK's shipped hashes are real, not placeholders.** The four
  `rtk-0.44.2-*` rows in `install.checksums` are genuine pinned hashes carried
  over from the original installer, verified rather than fabricated.
- **Windows parity is code-complete but less battle-tested.**
  `install.ps1` mirrors `install.sh`'s checksum gating, pinned-commit clone,
  and `-AllowUnpinned`/`-RefreshChecksums` flags (plus enforcing TLS 1.2 for
  its own downloads), but a full Windows install smoke test has not been run
  in this fork's CI — see [Verification](#verification).

### Pinned supply chain

Instead of installing from an unversioned `main.zip`, both installers clone
the repository and check out a specific commit before installing:

```bash
git clone https://github.com/alishahryar1/free-claude-code
git -C free-claude-code checkout --detach "$FCC_COMMIT"
```

The script then verifies the checked-out `HEAD` equals the pinned commit
before proceeding, and installs with `uv tool install --locked` (when the
resolved `uv` supports `--locked`), so the resolved `uv.lock` dependency
closure is honored rather than allowed to float. The pinned commit is
overridable for testing or auditing a different revision:

```bash
scripts/install.sh --fcc-ref <full-40-char-commit-sha>
```

Passing a ref that isn't a full 40-character commit SHA (a branch or tag
name) still works but is **not** cryptographically pinned, and the installer
warns accordingly.

### Secure-by-default runtime

The proxy server (`fcc-server`) is closed to the network unless you
deliberately open it up:

- **`HOST` defaults to loopback (`127.0.0.1`).** The server binds only to the
  local machine unless you explicitly set `HOST` to something else.
- **Proxy authentication is on by default**, using a cryptographically-random
  per-install token (`secrets.token_urlsafe`, 32 bytes) auto-generated on
  first run and persisted at `~/.fcc/proxy_auth_token` with owner-only (`0600`)
  permissions, inside a `0700` `~/.fcc` directory. The shipped config default
  (`ANTHROPIC_AUTH_TOKEN`/`freecc`) is never treated as a real credential —
  it's a placeholder that always triggers generation of a real one.
  Every `fcc-*` launcher (`fcc-claude`, `fcc-codex`, `fcc-desktop`, ...) reads
  the same generated token and sets it for the client automatically, so there
  is no manual setup step.
- **A startup exposure fail-safe refuses to bind a non-loopback interface**
  unless auth is enabled with a token that isn't the public default. This is
  enforced on *every* bind and rebind — the CLI entrypoint, the `fcc-desktop`
  path, and admin-triggered in-process restarts all go through the same
  check inside `ServerSupervisor._run_once`, not just a one-time check at
  process start.
- **`TrustedHostMiddleware`** validates the inbound `Host` header. Loopback
  binds get a strict allowlist (`localhost`, `127.0.0.1`, `::1`/`[::1]`, plus
  any hosts you add via `TRUSTED_HOSTS`); a deliberate all-interfaces bind
  (e.g. `HOST=0.0.0.0` in the container image) with no explicit
  `TRUSTED_HOSTS` leaves Host checking off and relies on proxy auth instead —
  listing hosts via `TRUSTED_HOSTS` re-enables strict checking on that bind.
- **Request bodies over `MAX_REQUEST_BODY_BYTES` (100 MiB default) are
  rejected with HTTP 413** before being buffered — both for a declared
  `Content-Length` over the cap and for unbounded/chunked bodies, which are
  cut off as soon as they cross the cap rather than being fully read first.

### Admin & SSRF hardening

- **Admin routes are loopback-gated in depth.** `require_loopback_admin`
  rejects any request that (a) carries a forwarded-request header
  (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `Forwarded` — not
  trusted for the loopback decision even behind a permissive reverse proxy),
  (b) doesn't originate from a loopback transport peer, (c) has a `Host`
  header outside a loopback/`testserver` allowlist (closing a DNS-rebinding
  path where a malicious page's JS, from a rebound hostname, could otherwise
  reach `127.0.0.1` with an attacker-chosen `Host`), or (d) has a non-local
  `Origin`.
- **`web_fetch` is guarded against SSRF** by a DNS-pinned resolver (the
  connection is made to the address that was validated, closing the
  resolve-then-connect TOCTOU window), a block on private/loopback/
  link-local/CGNAT/cloud-metadata (`169.254.169.254`) targets, IPv4-in-IPv6
  embedding detection covering IPv4-mapped, 6to4, Teredo, *and* NAT64
  (including arbitrary RFC 6052 custom prefixes, not just the well-known
  `64:ff9b::/96` one), per-hop re-validation on every redirect, and a scheme
  allowlist.
- **The admin local-provider probe (LM Studio/llama.cpp/Ollama reachability
  check) is routed through the same egress guard**, with loopback targets
  specifically allowed (that's the probe's whole purpose) while every other
  private/link-local/metadata address is still rejected — closing a path
  where a corrupted or malicious local-provider URL in config could otherwise
  be used to probe internal/cloud-metadata addresses.

### Messaging authorization

Telegram inbound message handling is **fail-closed**: if
`ALLOWED_TELEGRAM_USER_ID` is unset, every inbound message is rejected (and
logged) rather than accepted from any Telegram user, matching the existing
Discord behavior. Previously, an unset allowlist meant *any* Telegram user
could drive the managed coding-agent subprocess.

### Dependencies & supply-chain scanning

- **Explicit CVE floors** on transitive dependencies that could otherwise
  resolve to vulnerable versions under `fastapi`/`httpx`/`requests`/
  `google-auth`'s own looser constraints: `starlette>=1.6.0`,
  `python-multipart>=0.0.32`, `urllib3>=2.7.0`, `cryptography>=50.0.0`,
  `idna>=3.19` — each pinned to a version that closes a specific published
  advisory (see the comments beside each pin in `pyproject.toml`). The
  `starlette` floor pulls in `httpx2` (its 1.x `TestClient` dependency),
  pinned separately so its own deprecation warning doesn't become fatal under
  this project's `filterwarnings=error` test config.
- **CI runs Ruff's `S` (flake8-bandit) ruleset** — hardcoded binds/secrets,
  unsafe subprocess usage, weak crypto, and similar security lint checks — in
  addition to the existing formatting/lint/type/test gates.
- **`deps-audit`** runs `pip-audit` (via `uvx`) against the locked dependency
  set on every CI run, and is available locally:

  ```bash
  ./scripts/ci.sh --only deps-audit
  ```

- **`secrets-scan`** runs `gitleaks` over full repository history in CI to
  catch committed credentials.
- These sit on top of the existing SHA-pinned GitHub Actions (no floating
  `@v4`-style action tags) and `uv tool install --locked` supply-chain
  pinning from the installer hardening above.

### Containerized, isolated runtime

[`Dockerfile`](Dockerfile), [`docker-compose.yml`](docker-compose.yml), and
[`.dockerignore`](.dockerignore) define an isolated deployment for the
`fcc-server` proxy:

- Runs as a fixed non-root user (uid/gid `10001`), never root.
- Root filesystem is `read_only: true`; only sized `tmpfs` mounts (`/tmp`,
  `/home/fcc`) are writable, matching everywhere the app itself writes state
  (logs, messaging session state, the OpenAI/Codex credential cache).
- `cap_drop: ALL` and `security_opt: no-new-privileges:true`.
- Resource ceilings: `pids_limit`, `mem_limit`, `mem_reservation`, `cpus`.
- The proxy port is published loopback-only (`127.0.0.1:8082:8082`), never on
  a LAN- or internet-reachable interface. The image deliberately sets
  `HOST=0.0.0.0` *inside* the container (required for Docker's container-to-host
  port mapping to work at all) — this is still safe because proxy auth is on
  by default, the port is only ever published to the host's loopback address,
  and the exposure fail-safe would refuse the bind anyway if auth were somehow
  off.
- Secrets come from `env_file: .env`, read once at container creation — never
  baked into the image or bind-mounted as a browsable file.
- `docker-compose.yml` documents host paths that must **never** be
  bind-mounted into any service — `~/.aws`, `~/.kube`, `~/.ssh`,
  `~/.config/gcloud`, `~/.docker`, `/var/run/docker.sock`, `~/.anthropic`,
  `~/.claude` — since any of these hands the container a real credential
  store or, in the Docker-socket case, effective host root.

Build and run it with:

```bash
docker compose up --build
```

### Egress filtering

`fcc-server` sits on an `internal: true` Docker network with no default
route to the internet. The only way out is a Squid sidecar
([`egress/squid.conf`](egress/squid.conf)) on a second network, enforcing a
deny-by-default `dstdomain` allowlist
([`egress/allowed-domains.txt`](egress/allowed-domains.txt)) of the ~42
provider hosts this codebase actually calls (extracted from
`provider_catalog.py`), plus two regex ACLs for Bedrock Mantle and Vertex
AI's region-varying hostnames. Squid tunnels TLS (`CONNECT`) without
terminating it — no `ssl_bump`, no injected CA — so request/response bodies,
including auth headers, stay end-to-end encrypted between `fcc-server` and
the provider; Squid only ever sees the destination hostname and port.

To allow an additional host, add it to `egress/allowed-domains.txt` and
reload:

```bash
docker compose exec egress-proxy squid -k reconfigure
```

### Source audit tooling

[`scripts/audit.sh`](scripts/audit.sh) is a heuristic, grep-based scan of the
Python source tree for patterns that look like unauthorized secret logging or
exfiltration — env-var dumps, headers/tokens passed into `print()`/`logger.*`,
secret-shaped values written to disk, and outbound HTTP calls carrying
secret-shaped payloads.

```bash
scripts/audit.sh
```

Findings are tagged **HIGH** or one of several INFO-tier labels
(`ALLOWLISTED`, `GATED`, `REDACTED`, `REVIEW`). The script exits `1` only if
a **HIGH** finding remains — those warrant a direct look at the surrounding
code. INFO-tier findings (e.g. a match near a `LOG_RAW_*` debug flag, near a
`redact*()` helper, or a static message that merely mentions a keyword like
"token") still print for visibility but don't fail the scan; `EXFIL` matches
are always INFO-tier (`REVIEW`) at most, since this proxy's entire job is
forwarding a credential to an upstream provider and grep cannot tell an
intended provider host from an attacker-controlled one.

### Verification

- **The full check suite is green on Python 3.14 via `uv`:** `ruff format
  --check`, `ruff check`, `ty`, the full `pytest` suite, and the Playwright
  `e2e` suite all pass, run with:

  ```bash
  ./scripts/ci.sh
  ```

- **`deps-audit` (`pip-audit`) and `secrets-scan` (`gitleaks`) run on GitHub
  CI** for every pull request and are not currently required-status-check
  gated the same way the other jobs are — see the open follow-up below.
- **Windows (`install.ps1`) is unverified by an actual run.** Its checksum
  gating, pinned-commit clone, and flag surface mirror `install.sh` line for
  line, but no Windows machine has run it end-to-end in this fork's CI or
  development. Treat it as code-reviewed, not smoke-tested, until that gap
  is closed.

### Caveats and limitations

- **Rolling vendor installers are trust-on-first-use, not vendor-pinned.**
  Claude Code, Codex, Pi, OpenCode, Hermes, Grok Build, and Muse Code publish
  no stable upstream checksum for their install scripts, so `--refresh-checksums`
  pins the exact bytes you personally reviewed at that moment — not a hash
  the vendor itself published. It also only pins the *installer script*, not
  the binaries or packages that script subsequently downloads and installs.
- **Container base images are tag-pinned, not digest-pinned.** `python:3.14-slim`,
  `ghcr.io/astral-sh/uv`, and `ubuntu/squid:latest` are referenced by tag.
  A specific current digest could not be verified from the environment this
  fork was authored in, and fabricating a digest would be worse than leaving
  it tag-pinned. Resolve and pin `@sha256:<digest>` for each image before any
  production deployment.
- **`web_fetch` does not work under this egress topology, and it's not just
  an allowlist gap.** It opens its own DNS-pinned connection and defaults to
  ignoring proxy environment variables, so it never reaches the Squid
  sidecar at all — fixing it requires a code change (passing `trust_env`/an
  explicit proxy through to its HTTP client), not a config change.
  `web_search` does go through the proxy but is blocked by default because
  its target isn't an LLM provider host; add it to
  `egress/allowed-domains.txt` if you want it enabled.
- **`scripts/audit.sh` is a heuristic pattern scan, not a parser or a taint
  analyzer.** It can miss a secret laundered through an extra variable or
  dynamic attribute access, and it can flag a line that only mentions a
  keyword in English prose. Treat it as a prompt for human review, not proof
  of safety.
- **The checksum manifest ships mostly unpopulated.** Only RTK's four hashes
  are pre-filled; every vendor installer and `uv` platform row starts as
  `REPLACE_ME` until you run `--refresh-checksums` yourself and paste in
  reviewed hashes — by design, so no hash is ever fabricated on your behalf.
- **Managed coding agents run with `--dangerously-skip-permissions`.** This
  is inherent to running an autonomous coding agent unattended (it can't stop
  to ask a human for every file edit or shell command); the real barrier
  against an untrusted third party driving that agent is the fail-closed
  messaging allowlists (Telegram `ALLOWED_TELEGRAM_USER_ID`, Discord's
  equivalent) documented above — not a sandboxed subprocess.
- **This is a private, unaudited fork.** It has not been independently
  audited, and no third party has certified any of the controls described
  above. Two internal remediation passes are tracked in
  [`SECURITY-FINDINGS.md`](SECURITY-FINDINGS.md), including their accepted
  residual risk, but that document is not a substitute for external review.
- **Documented open follow-ups** (tracked in
  [`SECURITY-FINDINGS.md`](SECURITY-FINDINGS.md)): the admin-facing
  provider-connectivity test (`services.admin.test_provider`) calls the
  provider client abstraction rather than a raw guarded request, so it isn't
  covered by the `web_fetch`/local-provider-probe SSRF guard yet; an admin
  can still *persist* an unsafe `HOST`/auth config through the admin API even
  though the exposure fail-safe now blocks it from ever taking effect on a
  bind, so rejecting it at apply-time is further hardening, not yet done;
  and `deps-audit`/`secrets-scan` are not yet enforced as required
  branch-protection status checks.


## What You Get

- **48 ToS-friendly providers. 1.3B+ free tokens every month.** Use free, paid, subscription, and local models from one searchable UI without putting your account at risk. FCC follows provider terms and removes integrations if they stop being allowed.
- **9 coding agents. One model catalog.** Run [Claude Code](https://code.claude.com/docs/en/overview), [Codex](https://github.com/openai/codex), [Pi](https://github.com/earendil-works/pi), [OpenCode](https://github.com/anomalyco/opencode), [Cline](https://github.com/cline/cline), [Hermes](https://github.com/NousResearch/hermes-agent), [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness), [Grok Build](https://github.com/xai-org/grok-build), or [Muse Code](https://research.meta.ai/blog/introducing-muse-code-and-muse-spark-1-2/) with your FCC models.
- **Keep coding through provider outages.** After retries are exhausted, FCC automatically tries your next configured model without making you restart the turn—across every client.
- **Up to 90% fewer terminal-output tokens.** Optional [RTK](https://github.com/rtk-ai/rtk) filters common command output, while five FCC optimizations handle quota probes, command-prefix detection, titles, suggestions, and filepaths without calling a provider.
- **Terminal, desktop, IDE, or phone.** Work through native launchers, [VS Code](https://code.visualstudio.com/), [Codex App](https://learn.chatgpt.com/docs/app), [JetBrains](https://www.jetbrains.com/), [Discord](https://discord.com/), or [Telegram](https://telegram.org/).
- **Voice notes in. Code out.** Talk to your agent using local [Whisper](https://github.com/openai/whisper) or [NVIDIA NIM](https://docs.nvidia.com/nim/speech/latest/asr/deploy-asr-models/whisper.html) transcription.
- **Agent capabilities stay intact.** Stream responses, use tools, preserve native interleaved thinking for maximum performance, send images, and route [Fable](https://www.anthropic.com/claude/fable), [Opus](https://www.anthropic.com/claude/opus), [Sonnet](https://www.anthropic.com/claude/sonnet), and [Haiku](https://www.anthropic.com/claude/haiku) independently with compatible models.

Free-tier availability and limits are controlled by each provider and may change.

<div align="center">
  <img src="assets/pic.png" alt="Claude Code running with Free Claude Code" width="700">
  <p><em>Claude Code running with FCC.</em></p>
</div>

## Quick Start

<a id="install"></a>

### 1. Install Or Update

macOS/Linux:

```bash
curl -fsSL "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/install.sh" | sh
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/install.ps1")))
```

Re-run the same command to update. When prompted, choose at least one coding agent and optionally RTK. You can review the installers before running them: [install.sh](scripts/install.sh) and [install.ps1](scripts/install.ps1).

### 2. Start FCC

#### Windows

Open **Free Claude Code** from your desktop or Start menu.

#### macOS

Open **Free Claude Code** from your desktop or Applications folder.

#### Linux

Run:

```bash
fcc-server
```

FCC opens the Admin UI after starting. On Windows and macOS, use the tray or
menu-bar icon to open Admin, restart, or quit. When using `fcc-server`, keep its
terminal open.

<a id="nvidia-nim-provider"></a>

### 3. Configure NVIDIA NIM

1. Create an API key at [build.nvidia.com/settings/api-keys](https://build.nvidia.com/settings/api-keys).
2. Open the Admin UI URL from the server log.
3. Paste the key into `NVIDIA_NIM_API_KEY`.
4. Leave `MODEL` on the default `nvidia_nim/nvidia/nemotron-3-super-120b-a12b`, or search the model dropdown and select another model.
5. Click **Validate**, then **Apply**.

To protect the local proxy with a bearer token, enable **Proxy Authentication**
in Admin.

<div align="center">
  <img src="assets/admin-page.png" alt="Free Claude Code Admin UI" width="700">
</div>

### 4. Run Your Coding Agent

Claude Code:

```bash
fcc-claude
```

Codex:

```bash
fcc-codex
```

Pi:

```bash
fcc-pi
```

OpenCode:

```bash
fcc-opencode
```

Cline:

```bash
fcc-cline
```

Hermes:

```bash
fcc-hermes
```

DeepSeek Harness Web:

```bash
fcc-dsh
```

DeepSeek Harness headless:

```bash
fcc-dsh --profile headless "your task"
```

Grok Build:

```bash
fcc-grok
```

Muse Code:

```bash
fcc-muse
```

All nine launchers use the current Admin UI settings. Use the agent's model picker to choose from the models FCC exposes. Normal CLI arguments still work, for example:

```bash
fcc-codex exec "hello"
```

FCC launchers leave your existing agent settings, sessions, credentials, and
extensions unchanged. `fcc-hermes` starts attached sessions through FCC; choosing
another provider with Hermes `/model` intentionally leaves the FCC route.
`fcc-dsh` keeps DeepSeek Harness sessions and plugins while applying temporary
FCC provider settings. It currently supports the preview release `0.1.0-rc.8`
on Node.js `^22.19` or `>=24`.
`fcc-grok` keeps Grok Build's sessions and plugins, while routing attached
sessions through FCC. Web search and fetch stay disabled until FCC supports
Grok Build's Responses-side web-tool contract.
`fcc-muse` keeps Muse Code's native sessions and settings while routing attached
sessions through FCC. Muse is beta; Meta's official installer currently supports
macOS, Linux, and WSL, while Windows requires a compatible preinstalled binary.

<a id="model-picker"></a>

<div align="center">
  <img src="assets/cc-model-picker.png" alt="Claude Code model picker showing FCC models" width="700">
  <p><em>Select an FCC model from Claude Code's native <code>/model</code> picker.</em></p>
</div>

## Choose A Provider

1. Open a provider link below for its key, models, or setup instructions.
2. In the Admin UI, configure the listed setting. For OpenAI, use
   **Providers → Connected accounts** instead.
3. Search the `MODEL` dropdown and select a model. If the provider cannot list
   models, enter `<provider-id>/<exact-provider-model-id>` manually.
4. Click **Validate**, then **Apply**.

Optional: add an ordered **Fallback Models** list under **Model Config**. It
applies to every connected client. A failed request may reach and consume usage
from more than one provider before succeeding.

<details>
<summary><strong>Provider catalog</strong></summary>

| Provider | Admin UI setting | Example `MODEL` |
| --- | --- | --- |
| [NVIDIA NIM](https://build.nvidia.com/settings/api-keys) | `NVIDIA_NIM_API_KEY` | `nvidia_nim/nvidia/nemotron-3-super-120b-a12b` |
| [OpenRouter](https://openrouter.ai/keys) | `OPENROUTER_API_KEY` | `open_router/openrouter/free` |
| [Groq](https://console.groq.com/keys) | `GROQ_API_KEY` | `groq/llama-3.3-70b-versatile` |
| [ClinePass](https://docs.cline.bot/getting-started/clinepass) | `CLINE_API_KEY` | `cline_pass/cline-pass/kimi-k3` |
| [OpenAI / ChatGPT](https://learn.chatgpt.com/docs/auth) | Connect ChatGPT in the Admin UI | `openai/<model-id>` |
| [xAI (Grok)](https://console.x.ai/team/default/api-keys) | `XAI_API_KEY` | `xai/grok-4.5` |
| [QwenCloud Token Plan](https://home.qwencloud.com/api-keys) | `QWENCLOUD_API_KEY` | `qwencloud/qwen3.7-plus` |
| [QwenCloud Coding Plan](https://home.qwencloud.com/api-keys) | `QWENCLOUD_CODING_API_KEY` | `qwencloud_coding/qwen3.7-plus` |
| [Together AI](https://api.together.ai/settings/api-keys) | `TOGETHER_API_KEY` | `together/zai-org/GLM-5.2` |
| [DeepInfra](https://deepinfra.com/dash/api_keys) | `DEEPINFRA_API_KEY` | `deepinfra/deepseek-ai/DeepSeek-V4-Flash` |
| [SiliconFlow](https://cloud.siliconflow.com/account/ak) | `SILICONFLOW_API_KEY` | `siliconflow/Qwen/Qwen3-32B` |
| [Nebius Token Factory](https://tokenfactory.nebius.com/project/api-keys) | `NEBIUS_API_KEY` | `nebius/Qwen/Qwen3-30B-A3B` |
| [Chutes](https://chutes.ai/docs/getting-started/authentication) | `CHUTES_API_KEY` | `chutes/Qwen/Qwen3-32B-TEE` |
| [Featherless AI](https://featherless.ai/account/api-keys) | `FEATHERLESS_API_KEY` | `featherless/Qwen/Qwen3-32B` |
| [Agnes AI](https://agnes-ai.com/) | `AGNES_API_KEY` | `agnes/agnes-2.0-flash` |
| [ZenMux](https://zenmux.ai/platform/pay-as-you-go) | `ZENMUX_API_KEY` | `zenmux/deepseek/deepseek-v4-flash-free` |
| [W&B Inference](https://wandb.ai/settings) | `WANDB_API_KEY` | `wandb/openai/gpt-oss-20b` |
| [Azure OpenAI](https://learn.microsoft.com/azure/foundry/openai/how-to/chatgpt) | `AZURE_OPENAI_API_KEY` and `AZURE_OPENAI_BASE_URL` | `azure_openai/<deployment-name>` |
| [Google AI Studio (Gemini)](https://aistudio.google.com/apikey) | `GEMINI_API_KEY` | `gemini/models/gemini-3.1-flash-lite` |
| [Google Vertex AI](https://cloud.google.com/vertex-ai/generative-ai/docs/start/openai) | `VERTEX_PROJECT_ID` + ADC | `vertex/google/gemini-3.5-flash` |
| [DeepSeek](https://platform.deepseek.com/api_keys) | `DEEPSEEK_API_KEY` | `deepseek/deepseek-chat` |
| [Mistral La Plateforme](https://console.mistral.ai/) | `MISTRAL_API_KEY` | `mistral/devstral-small-latest` |
| [Mistral Codestral](https://console.mistral.ai/) | `CODESTRAL_API_KEY` | `mistral_codestral/codestral-latest` |
| [OpenCode Zen](https://opencode.ai/auth) | `OPENCODE_API_KEY` | `opencode_zen/gpt-5.3-codex` |
| [OpenCode Go](https://opencode.ai/auth) | `OPENCODE_API_KEY` | `opencode_go/minimax-m2.7` |
| [Vercel AI Gateway](https://vercel.com/docs/ai-gateway/models-and-providers) | `AI_GATEWAY_API_KEY` | `vercel/openai/gpt-5.5` |
| [Amazon Bedrock](https://console.aws.amazon.com/bedrock/) | `AWS_BEARER_TOKEN_BEDROCK` | `bedrock/openai.gpt-oss-120b` |
| [Hugging Face Inference Providers](https://huggingface.co/settings/tokens) | `HUGGINGFACE_API_KEY` | `huggingface/Qwen/Qwen3-Coder-480B-A35B-Instruct:fastest` |
| [Cohere](https://dashboard.cohere.com/api-keys) | `COHERE_API_KEY` | `cohere/command-a-plus-05-2026` |
| [GitHub Models](https://github.com/marketplace?type=models) | `GITHUB_MODELS_TOKEN` | `github_models/openai/gpt-4.1` |
| [Wafer](https://wafer.ai/) | `WAFER_API_KEY` | `wafer/DeepSeek-V4-Pro` |
| [Kimi API](https://platform.moonshot.ai/console/api-keys) | `KIMI_API_KEY` | `kimi/kimi-k2.5` |
| [Kimi Code](https://www.kimi.com/code/console) | `KIMI_CODE_API_KEY` | `kimi_code/k3` |
| [MiniMax](https://platform.minimax.io/user-center/basic-information/interface-key) | `MINIMAX_API_KEY` | `minimax/MiniMax-M3` |
| [Cerebras Inference](https://cloud.cerebras.ai/) | `CEREBRAS_API_KEY` | `cerebras/gpt-oss-120b` |
| [SambaNova](https://cloud.sambanova.ai/apis) | `SAMBANOVA_API_KEY` | `sambanova/Meta-Llama-3.3-70B-Instruct` |
| [Kilo.ai](https://kilo.ai) | `KILO_API_KEY` | `kilo/kilo-auto/free` |
| [Fireworks AI](https://fireworks.ai/account/api-keys) | `FIREWORKS_API_KEY` | `fireworks/accounts/fireworks/models/llama-v3p3-70b-instruct` |
| [Novita AI](https://novita.ai/settings/key-management) | `NOVITA_API_KEY` | `novita/deepseek/deepseek-v4-flash-0731` |
| [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/) | `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` | `cloudflare/@cf/moonshotai/kimi-k2.6` |
| [Z.ai Coding Plan](https://z.ai/manage-apikey/apikey-list) | `ZAI_API_KEY` | `zai/glm-5.2` |
| [Z.ai API (pay as you go)](https://z.ai/manage-apikey/apikey-list) | `ZAI_API_KEY` | `zai_api/glm-4.7-flash` |
| [TokenRouter](https://www.tokenrouter.com/) | `TOKENROUTER_API_KEY` | `tokenrouter/moonshotai/kimi-k3-free` |
| [NaraRoute](https://router.bynara.id/) | `NARAROUTE_API_KEY` | `nararoute/kimi-k3-free` |
| [Ollama Cloud](https://ollama.com/settings/keys) | `OLLAMA_API_KEY` | `ollama_cloud/qwen3-coder:480b` |
| [LM Studio](https://lmstudio.ai/) | `LM_STUDIO_BASE_URL` | `lmstudio/<model-id>` |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) | `LLAMACPP_BASE_URL` | `llamacpp/<model-id>` |
| [Ollama](https://ollama.com/) | `OLLAMA_BASE_URL` | `ollama/<model-tag>` |

</details>

<details>
<summary><strong>Provider-specific setup</strong></summary>

- OpenAI uses your ChatGPT subscription rather than an API key. Connect from
  **Providers → Connected accounts** in the Admin UI. Use device code on
  headless systems. Restart an already-running agent after connecting.
- Azure OpenAI uses the deployment names from your resource. Set
  `AZURE_OPENAI_BASE_URL` to its complete v1 endpoint, such as
  `https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1/`, and select a
  deployment that supports Chat Completions. Enter the deployment name as a
  custom model slug if it does not appear in the model dropdown.
- Mistral Codestral uses a separate key from Mistral La Plateforme.
- Kimi Code subscription keys use `kimi_code/`; Kimi API credit keys use
  `kimi/`. Kimi Code plans are for personal interactive coding-agent use under
  [Kimi's community guidelines](https://www.kimi.com/code/docs/en/kimi-code/community-guidelines.html).
- QwenCloud Coding Plan keys use `qwencloud_coding/`; QwenCloud Token Plan keys
  use `qwencloud/`. The keys and endpoints are not interchangeable. Coding Plan
  is for local, personal, interactive coding-agent use under the
  [Coding Plan terms](https://www.alibabacloud.com/help/en/model-studio/coding-plan).
- OpenCode Zen and OpenCode Go share `OPENCODE_API_KEY` but use the explicit
  `opencode_zen/` and `opencode_go/` model prefixes.
- For Amazon Bedrock, set `BEDROCK_BASE_URL` to the URL for the same region as
  the API key and select one of the listed models.
- Vertex AI uses Google Application Default Credentials instead of an API key.
  Locally, run `gcloud auth application-default login` once; service-account
  files and attached service accounts also work. Set `VERTEX_PROJECT_ID`, and
  optionally change `VERTEX_LOCATION` from its `global` default.
- Cloudflare requires both its API token and account ID.
- For Ollama Cloud, use the exact model IDs shown in the model picker. Local
  Ollama uses the separate `ollama/` prefix.
- Prefer tool-capable models for coding agents. Local models also need enough context for the agent's system prompt and tool definitions.

</details>

<details>
<summary><strong>Local provider setup</strong></summary>

### LM Studio

Start LM Studio's local server, load a tool-capable model, and use the model identifier shown by LM Studio with the `lmstudio/` prefix. The default URL is `http://localhost:1234/v1`.

### llama.cpp

Start `llama-server` with its OpenAI-compatible Chat Completions API and enough context for the model. Use the local model ID with the `llamacpp/` prefix. `LLAMACPP_BASE_URL` defaults to `http://localhost:8080/v1`; FCC accepts either the server root or an explicit `/v1` suffix.

### Ollama

```bash
ollama pull llama3.1
ollama serve
```

Use the tag shown by `ollama list` with the `ollama/` prefix. `OLLAMA_BASE_URL` defaults to `http://localhost:11434`; FCC accepts either the root URL or an explicit `/v1` suffix.

</details>

<details>
<summary><strong>Optional model-tier routing</strong></summary>

`MODEL` is the fallback for every request. Select a model for `MODEL_FABLE`, `MODEL_OPUS`, `MODEL_SONNET`, or `MODEL_HAIKU` to override an individual Claude Code tier; select **None** to use `MODEL`.

For example, route Opus to `nvidia_nim/nvidia/nemotron-3-super-120b-a12b`, Sonnet to `open_router/openrouter/free`, Haiku to `lmstudio/qwen3.5-coder`, and keep `MODEL` on `zai/glm-5.2`.

</details>

<details>
<summary><strong>Reasoning control</strong></summary>

Open **Admin UI → Model Config → Reasoning** and select the behavior you want.

| Selection | Behavior |
| --- | --- |
| **From client** (default) | Use the effort sent by Claude Code, Codex, Pi, OpenCode, Cline, Hermes, DeepSeek Harness, Grok Build, or Muse Code. If none is sent, keep the provider default. |
| **Off** | Request reasoning to be disabled. |
| **Low**, **Medium**, **High**, **X-High**, or **Max** | Override the client with the selected reasoning level. |
| **Inherit** (Fable, Opus, Sonnet, and Haiku only) | Use the root Reasoning selection. |

Providers that do not support a selected control retain their own behavior.

</details>

<a id="connect-your-client"></a>

## Connect Your Client

For terminal use, start `fcc-server`, then run `fcc-claude`, `fcc-codex`,
`fcc-pi`, `fcc-opencode`, `fcc-cline`, `fcc-hermes`, `fcc-dsh`, `fcc-grok`, or
`fcc-muse`.
Use the guides below for editor integrations.

<details>
<summary><strong>Claude Code in VS Code</strong></summary>

Install the [Claude Code extension](https://marketplace.visualstudio.com/items?itemName=anthropic.claude-code). Open VS Code's user settings as JSON and add:

```json
"claudeCode.disableLoginPrompt": true,
"claudeCode.environmentVariables": [
  { "name": "ANTHROPIC_BASE_URL", "value": "http://localhost:8082" },
  { "name": "ANTHROPIC_AUTH_TOKEN", "value": "freecc" },
  { "name": "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY", "value": "1" },
  { "name": "CLAUDE_CODE_AUTO_COMPACT_WINDOW", "value": "190000" },
  { "name": "DISABLE_AUTOUPDATER", "value": "1" },
  { "name": "DISABLE_FEEDBACK_COMMAND", "value": "1" },
  { "name": "DISABLE_ERROR_REPORTING", "value": "1" }
]
```

Match the port and authentication token to the Admin UI, then reload the extension.

</details>

<details>
<summary><strong>Codex App</strong></summary>

Start FCC, then edit your Codex configuration:

- Windows: `%USERPROFILE%\.codex\config.toml`
- macOS: `~/.codex/config.toml`

Add the matching model-catalog path and replace `YOUR_USERNAME`.

Windows:

```toml
model_catalog_json = "C:/Users/YOUR_USERNAME/.fcc/codex-model-catalog.json"
```

macOS:

```toml
model_catalog_json = "/Users/YOUR_USERNAME/.fcc/codex-model-catalog.json"
```

Then add the shared FCC settings:

```toml
model_provider = "fcc"
model = "nvidia_nim/nvidia/nemotron-3-super-120b-a12b"

[model_providers.fcc]
name = "Free Claude Code"
base_url = "http://127.0.0.1:8082/v1"
wire_api = "responses"

[model_providers.fcc.auth]
command = "fcc-codex"
args = ["--print-proxy-auth-token"]
```

Match the model and port to the Admin UI. The auth command reads FCC's current
proxy token automatically. Restart the Codex App after setup or model changes,
then select an FCC model from its model picker.

</details>

<details>
<summary><strong>Codex in VS Code</strong></summary>

Install the [Codex extension](https://marketplace.visualstudio.com/items?itemName=openai.chatgpt). Create or edit `~/.codex/config.toml` (`%USERPROFILE%\.codex\config.toml` on Windows):

```toml
model_provider = "fcc"
model = "nvidia_nim/nvidia/nemotron-3-super-120b-a12b"

[model_providers.fcc]
name = "Free Claude Code"
base_url = "http://127.0.0.1:8082/v1"
wire_api = "responses"

[model_providers.fcc.auth]
command = "fcc-codex"
args = ["--print-proxy-auth-token"]
```

Match `model` and the port to the Admin UI. The auth command reads FCC's current
proxy token automatically. Restart VS Code after setup or model changes. For
WSL-backed Codex, edit the file inside WSL.

</details>

<details>
<summary><strong>Claude Code in JetBrains ACP</strong></summary>

Edit the installed Claude ACP configuration:

- Windows: `C:\Users\%USERNAME%\AppData\Roaming\JetBrains\acp-agents\installed.json`
- Linux/macOS: `~/.jetbrains/acp.json`

Set the environment for `acp.registry.claude-acp`:

```json
"env": {
  "ANTHROPIC_BASE_URL": "http://localhost:8082",
  "ANTHROPIC_AUTH_TOKEN": "freecc",
  "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY": "1",
  "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "190000",
  "DISABLE_AUTOUPDATER": "1",
  "DISABLE_FEEDBACK_COMMAND": "1",
  "DISABLE_ERROR_REPORTING": "1"
}
```

Match the port and token to the Admin UI, then restart the IDE.

</details>

<details>
<summary><strong>Claude Code still asks you to log in</strong></summary>

If Claude Code asks you to log in after you configure the FCC URL and token, open its state file:

- Windows: `%USERPROFILE%\.claude.json`
- macOS/Linux/WSL: `~/.claude.json`

Merge this property into the existing JSON without removing its other fields:

```json
"hasCompletedOnboarding": true
```

If the file does not exist, create it with a complete JSON object:

```json
{
  "hasCompletedOnboarding": true
}
```

Restart Claude Code or the IDE after saving the file.

</details>

<a id="optional-integrations"></a>

## Optional Integrations

Configure integrations from **Admin UI → Messaging**, then click **Validate** and **Apply**.

<details>
<summary><strong>Discord bot</strong></summary>

1. Create a bot in the [Discord Developer Portal](https://discord.com/developers/applications).
2. Enable **Message Content Intent** and invite it with read, send,
   message-history, and **Manage Messages** permissions so `/clear` can remove
   user prompts.
3. Set **Messaging Platform** to **discord**.
4. Enter **Discord Bot Token**, **Allowed Discord Channels**, and an absolute **Allowed Directory**.
5. Apply the settings and restart the server if requested.

</details>

<details>
<summary><strong>Telegram bot</strong></summary>

1. Create a bot with [@BotFather](https://t.me/BotFather).
2. Get your numeric user ID from [@userinfobot](https://t.me/userinfobot).
   In groups, grant the bot permission to delete messages.
3. Set **Messaging Platform** to **telegram**.
4. Enter **Telegram Bot Token**, **Allowed Telegram User ID**, and an absolute **Allowed Directory**.
5. Apply the settings and restart the server if requested.

</details>

### Messaging commands

| Usage | Behavior |
| --- | --- |
| `/stats` | Show session state. |
| Standalone `/stop` | Cancel all work. |
| Reply with `/stop` | Cancel only the selected request while other queued requests continue. |
| Standalone `/clear` | Reset all FCC state and remove every tracked message in that chat, including user prompts, voice notes, FCC replies, Telegram's online notice, and the clear command itself. |
| Reply with `/clear` | Delete the selected message and its literal platform reply subtree while preserving its ancestors and siblings. |

<details>
<summary><strong>Voice notes</strong></summary>

Choose the voice backend you want, then re-run the installer with its option.

| Voice backend | macOS/Linux option | Windows option |
| --- | --- | --- |
| NVIDIA NIM transcription | `--voice-nim` | `-VoiceNim` |
| Local Whisper on CPU or CUDA | `--voice-local` | `-VoiceLocal` |
| Both backends | `--voice-all` | `-VoiceAll` |
| Local Whisper with CUDA 13.0 | `--voice-local --torch-backend cu130` | `-VoiceLocal -TorchBackend cu130` |

The examples below install NVIDIA NIM transcription. To use another backend,
replace the final option with the matching one from the table.

macOS/Linux:

```bash
curl -fsSL "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/install.sh" | sh -s -- --voice-nim
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/install.ps1"))) -VoiceNim
```

Restart `fcc-server`. In **Admin UI → Messaging → Voice**, enable voice notes, select `cpu`, `cuda`, or `nvidia_nim`, and choose the Whisper model. Local gated models need `HUGGINGFACE_API_KEY`; NVIDIA NIM transcription needs `NVIDIA_NIM_API_KEY`.

</details>

## Manage Your Installation

Run `fcc-server --version` to check the installed version without starting FCC.

### Update

Re-run the matching command from [Install Or Update](#install).

### Uninstall

Stop every running FCC command before uninstalling.

**Removes**

- Free Claude Code, including its desktop launcher and commands
- `~/.fcc/`

**Keeps**

- uv and Python
- Claude Code, Codex, Pi, OpenCode, Cline, Hermes, DeepSeek Harness, Grok Build, Muse Code, and RTK
- Shared PATH entries

macOS/Linux:

```bash
curl -fsSL "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/uninstall.sh" | sh
```

Windows PowerShell:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/Alishahryar1/free-claude-code/main/scripts/uninstall.ps1")))
```


## Project Links

- [Architecture and extension guide](ARCHITECTURE.md)
- [Contributing guide](CONTRIBUTING.md)

## License

MIT License. See [LICENSE](LICENSE) for details.
