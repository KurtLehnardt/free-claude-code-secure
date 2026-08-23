# Sandboxed agent runner

This is the structural backstop for running the coding agent itself
(Claude Code, via `fcc-claude`) isolated, so that an untrusted or
compromised cloud LLM provider that is *steering the agent* cannot reach
host secrets or exfiltrate data — even if it fully controls every tool call
the agent makes.

It adds a second, separate isolation layer on top of the root
[`Dockerfile`](../Dockerfile)/[`docker-compose.yml`](../docker-compose.yml),
which already containerize `fcc-server` (the proxy) alone. This directory
containerizes the *agent process itself* too, in its own container, with no
route back to your host and no route to the internet except through
`fcc-server`.

## Threat model

Free Claude Code lets you point Claude Code at any configured LLM provider,
including free/low-cost third-party providers whose weights, prompts, and
output you do not control. That provider is an **untrusted upstream**:
anything it returns can be interpreted by the coding agent as instructions —
including tool calls. A malicious or compromised provider can try to steer
the agent into reading `~/.ssh/id_rsa`, dumping environment variables to a
remote server, or otherwise exfiltrating anything reachable from wherever
the agent process runs.

If the agent runs directly on your host (even via the already-containerized
`fcc-server`), the agent process itself still has your host's filesystem,
your shell history, your other credential stores, and a normal internet
connection. `hardening/README.md`'s `fcc-hook-guard` PreToolUse hook is a
best-effort regex filter against the most common patterns of that abuse —
explicitly documented there as fail-open and not a sandbox. This directory
is the actual sandbox: it makes the dangerous actions structurally
*impossible* for the classes covered below, not just heuristically blocked.

## What this isolates

Three containers, on two Docker networks:

```
                    ┌─────────────────────────────────────────┐
                    │            internal (no route            │
                    │             to the internet)             │
                    │                                            │
  /work  ──rw──▶ ┌──┴───────┐        ┌──────────┐               │
 (your project)  │ fcc-agent│◀──────▶│fcc-server│               │
                  │ (Claude  │  http  │ (proxy,  │               │
                  │  Code)   │        │ has keys)│               │
                  └──────────┘        └────┬─────┘               │
                    no other                │                    │
                    volumes,                │                    │
                    no other                ▼                    │
                    network            ┌──────────┐               │
                                       │egress-   │               │
                                       │proxy     │───────────────┼──▶ allowlisted
                                       │(Squid)   │               │    provider hosts
                                       └──────────┘               │    only
                    └─────────────────────────────────────────┘
                              egress-external (real internet,
                               ONLY egress-proxy is on it)
```

- **Host secrets are unreachable.** `fcc-agent` never mounts `~/.ssh`,
  `~/.aws`, `~/.kube`, `~/.config/gcloud`, `~/.docker`, `~/.anthropic`,
  `~/.claude`, `~/.fcc`, shell startup files, or any other host credential
  path — see the FORBIDDEN HOST MOUNTS block at the top of
  `docker-compose.yml`. It also never receives a provider API key: those
  live only in `fcc-server`'s environment (from `sandbox/.env`, via
  `env_file:`), and `fcc-agent` deliberately does **not** use `env_file:` at
  all — see the wiring note below.
- **Egress is structurally limited to the provider allowlist.** `fcc-agent`
  is a member of the `internal` Docker network ONLY (`internal: true` — no
  default route out at all) and is never added to `egress-external`. It can
  reach exactly one thing: `fcc-server`, by Docker service-name DNS, over
  plain HTTP. `fcc-server` itself can only reach the internet through the
  `egress-proxy` Squid sidecar, which allowlists provider hostnames by
  `dstdomain` (reusing `../egress/squid.conf` and
  `../egress/allowed-domains.txt` unmodified — see those files for why FQDN
  allowlisting needs an L7 proxy rather than plain Docker networking). A
  fully compromised `fcc-agent` process — one that opens a raw socket, runs
  `curl`, resolves a DNS name, anything — has no path to an arbitrary host,
  full stop. It is not relying on the agent's own good behavior or on
  `fcc-hook-guard` catching a pattern; there is no route.
- **The project directory is the only writable host path.** `fcc-agent`
  mounts exactly one host directory, at a fixed path (`/work`), read-write,
  set via `FCC_PROJECT_DIR`. Nothing else on the host is visible to it at
  all.

Both `fcc-agent` and `fcc-server` also carry the same hardening posture as
the root deployment: fixed non-root uid, `read_only: true` root filesystem
with sized `tmpfs` for the only paths that need to be writable, `cap_drop:
ALL`, `no-new-privileges:true`, and resource ceilings (`pids_limit`,
`mem_limit`, `cpus`).

## How the agent reaches `fcc-server` without host secrets

`fcc-claude` (the launcher `docker-compose.yml`'s `fcc-agent` runs as its
`CMD`) builds the URL it points Claude Code at from two settings fields,
`HOST`/`PORT`, resolved via `config/server_urls.py`'s
`local_proxy_root_url()`. `docker-compose.yml` sets those to
`HOST=fcc-server` / `PORT=8082` for the `fcc-agent` service — `fcc-server` is
resolvable by that name because both containers share the `internal`
network's embedded DNS. `fcc-claude` then preflights `http://fcc-server:8082/health`
and, on success, spawns `claude` with `ANTHROPIC_BASE_URL=http://fcc-server:8082`
and `ANTHROPIC_AUTH_TOKEN=<the proxy bearer token>` (see
`src/free_claude_code/cli/launchers/claude.py` and `cli/claude_env.py`).

That auth token is the **only** secret `fcc-agent` ever holds, and it only
grants access to `fcc-server`'s HTTP API on the internal network — it is not
a provider credential and cannot be used to call a provider directly. It has
to be set explicitly (see Setup below) and identically on both sides,
because each side would otherwise independently auto-generate its own
random token under its own container-local `~/.fcc` (see
`config/proxy_auth.py`), and two independently-generated tokens would never
match across two separate containers.

`docker-compose.yml`'s `fcc-agent` service deliberately does **not** use
`env_file: .env` the way `fcc-server` does. Only `ANTHROPIC_AUTH_TOKEN` is
pulled out of `sandbox/.env`, via Compose's `${ANTHROPIC_AUTH_TOKEN}`
*interpolation* (which Compose auto-loads from a `.env` file next to the
compose file, independent of any service's `env_file:` key). That is the
mechanism that keeps every `<PROVIDER>_API_KEY` in `sandbox/.env` out of
`fcc-agent`'s environment even though both services read from the same file
on disk — see the comments in `docker-compose.yml` right above the
`environment:` block for `fcc-agent`. Do not change `fcc-agent` to use
`env_file: .env`; that would hand it every provider key.

`fcc-hook-guard` (the default-on `PreToolUse` guard — see
[`../hardening/README.md`](../hardening/README.md)) also stays registered
inside `fcc-agent`, unmodified, as an additional heuristic layer underneath
this container boundary. It is not disabled here.

## Setup

From the repo root:

```bash
cp .env.example sandbox/.env
```

Edit `sandbox/.env`:

1. Fill in only the `<PROVIDER>_API_KEY` values you actually use — same as
   any other Free Claude Code setup. These stay in `fcc-server` only.
2. Set a real `ANTHROPIC_AUTH_TOKEN`, replacing the shipped `"freecc"`
   placeholder — `sandbox/docker-compose.yml` requires this (Compose will
   refuse to start `fcc-agent` with a clear error if it's unset/empty
   rather than silently falling back to the placeholder):

   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Paste the output as `ANTHROPIC_AUTH_TOKEN=...` in `sandbox/.env`.

`sandbox/.env` is already covered by the repo's root `.gitignore` (its bare
`.env` pattern matches at any depth) — it will not be committed.

## Running it

From inside the project directory you want the agent to work on:

```bash
FCC_PROJECT_DIR=$(pwd) docker compose -f /path/to/free-claude-code/sandbox/docker-compose.yml run --rm fcc-agent
```

(Adjust the path to wherever you checked out this repo. `FCC_PROJECT_DIR`
must be an absolute path — Compose fails fast with a clear error if it's
unset.) That starts `egress-proxy` and `fcc-server` first (`depends_on:
condition: service_healthy`), then drops you into an interactive `fcc-claude`
session with your project mounted read-write at `/work` inside the
container and nothing else from your host visible to it.

To pass arguments straight to `claude` (e.g. a one-shot prompt):

```bash
FCC_PROJECT_DIR=$(pwd) docker compose -f /path/to/free-claude-code/sandbox/docker-compose.yml run --rm fcc-agent -p "describe this repo"
```

Tear down with:

```bash
docker compose -f /path/to/free-claude-code/sandbox/docker-compose.yml down
```

## Honest limits — be precise about what this buys you

- **The provider still sees whatever the agent legitimately sends it.**
  This stops *local secret access* and *arbitrary-host exfiltration*; it does
  **not** stop the agent from sharing your project's own source/content with
  the configured provider as part of normal operation — that is the
  provider's whole job. If your threat model is "don't let this provider see
  my code at all," don't point it at that provider; this deployment doesn't
  change that decision for you.
- **`fcc-agent` has no internet access, by design — which also breaks
  anything in your project that needs it.** `npm install`, `pip install`,
  `git fetch`/`push` to a remote, downloading test fixtures, etc. will not
  work from inside `fcc-agent`, because it structurally has no route out
  (that's the isolation control, not a bug). Install/vendor dependencies on
  the host, into the project directory, **before** mounting it at `/work`,
  or run those specific commands outside the sandbox.
- **No named volume persists agent session state across runs.** `~/.claude`
  and `~/.fcc` inside `fcc-agent` live on `tmpfs` and are discarded when the
  container exits. This is a deliberate tradeoff (a persistent cache is one
  more place a secret or a poisoned artifact could quietly accumulate across
  runs), not an oversight — add a named volume yourself if you want
  cross-run history and accept that tradeoff.
- **Read-only rootfs is compatible with Claude Code's self-update, because
  it's already off.** `cli/claude_env.py`'s `build_claude_proxy_env()`
  unconditionally sets `DISABLE_AUTOUPDATER=1` for every `fcc-claude`
  launch (container or not) — confirmed by reading that source directly —
  so the read-only `/usr/local/lib/node_modules` here doesn't fight an
  update mechanism that would otherwise try to write to it.
- **Image digests are not pinned.** `python:3.14-slim`, `node:22-slim`, and
  `ubuntu/squid:latest` are all pinned by tag only, matching the same
  documented posture (and the same reason: no way to verify a current digest
  from this offline environment without fabricating one) as the root
  `Dockerfile`/`docker-compose.yml`. Resolve and pin `@sha256:<digest>` for
  all three before any real/production use — see the DIGEST-PIN REMINDER
  comments in `Dockerfile.agent`.
- **Claude Code itself is installed unpinned** (`@anthropic-ai/claude-code@latest`
  at build time, an `ARG CLAUDE_CODE_VERSION` you can override) — same
  trust-on-first-use posture the main `README.md` already documents for
  this vendor's rolling installer.
- **This has NOT been build-tested.** This environment has the `docker` CLI
  but no running Docker daemon (`docker info` fails with "no such file or
  directory" on the Docker socket), so `docker compose build` /
  `docker compose up` could not be exercised here. Validation performed
  instead:
  - `sandbox/docker-compose.yml` parses as valid YAML
    (`python3 -c "import yaml; yaml.safe_load(open('sandbox/docker-compose.yml'))"`)
    and was spot-checked by dumping the parsed structure back out.
  - Both Dockerfiles were hand-checked stage by stage against Docker's
    multi-stage build semantics (`ARG` scoping per stage, `COPY --from=`
    stage-name references, `ENV`/`WORKDIR`/`USER` ordering) and against the
    root `Dockerfile`'s already-established patterns.
  - The Compose fields used (`read_only`, `tmpfs` shorthand strings,
    `cap_drop`, `security_opt`, `mem_limit`/`mem_reservation`/`cpus`/
    `pids_limit`, `depends_on: condition: service_healthy`, `${VAR:?err}`
    required-variable interpolation) all match forms already used
    unmodified in the root `docker-compose.yml` or documented in the Compose
    Specification.
  - Neither `docker compose` (no CLI plugin installed here) nor
    `docker-compose` was available to run `config`/`--dry-run` validation in
    this environment either — treat this as code-reviewed, not
    build-tested, the same caveat the main `README.md` already applies to
    `install.ps1`.
  - Run a real `docker compose -f sandbox/docker-compose.yml config` and
    `... build` yourself before relying on this.
- **No `sandbox/.dockerignore` is shipped, on purpose.** `fcc-agent`'s
  builder stage needs repo-root files (`pyproject.toml`/`uv.lock`/`src/`),
  so its Compose `build.context` is `..` (the repo root), not `sandbox/`.
  Docker resolves an alternate-Dockerfile's ignore file by the Dockerfile's
  *basename* at the *context root* — i.e. it would look for
  `<repo-root>/Dockerfile.agent.dockerignore` — never a file under
  `sandbox/`. A `sandbox/.dockerignore` would therefore never be read by
  this build; it would just be a dead file that looks load-bearing and
  isn't. The build instead inherits the repo root's existing, already
  security-reviewed `.dockerignore` (excludes `.git`, `.env*`, `*.pem`/
  `*.key`, tests, caches, etc.) for free, since the context is the repo
  root either way.
- **`egress-proxy` and its allowlist are shared, unmodified, from the root
  deployment** (`../egress/squid.conf`, `../egress/allowed-domains.txt`).
  Its own documented caveats apply here too, unchanged — see that file's
  header comment, in particular around DNS behavior on `internal: true`
  networks and TLS `CONNECT`-tunnel (not `ssl_bump`) semantics.
