# syntax=docker/dockerfile:1
#
# fcc-server container image
# ---------------------------
# Multi-stage build for free-claude-code's proxy server (console script
# `fcc-server`, entry point `free_claude_code.cli.entrypoints:serve`).
#
# Verified against the real repo (src/free_claude_code):
#   - pyproject.toml: requires-python = ">=3.14.0", build-backend = hatchling,
#     [project.scripts] fcc-server = "free_claude_code.cli.entrypoints:serve"
#   - settings.py: HOST defaults to 0.0.0.0, PORT defaults to 8082
#   - api/routes.py: unauthenticated GET /health -> {"status": "healthy"}
#   - config/paths.py: ALL writable state (log file, messaging session state,
#     OpenAI/Codex credential cache, lock files) lives under
#     Path.home() / ".fcc" (config_dir_path()). Nothing writes relative to
#     the process CWD. That's why HOME is pinned to /home/fcc below and why
#     docker-compose.yml puts a tmpfs there instead of trying to guess every
#     individual sub-path.
#   - core/token_estimation.py: tiktoken.get_encoding("cl100k_base") lazily
#     downloads BPE rank data from openaipublic.blob.core.windows.net on
#     first use unless TIKTOKEN_CACHE_DIR already has it. Under the strict
#     egress allowlist in docker-compose.yml/egress/squid.conf that host is
#     NOT permitted (it isn't an LLM provider endpoint), so we warm the
#     tiktoken cache at build time (network is unrestricted during `docker
#     build`) and ship the cached file read-only in the runtime image. This
#     avoids a surprising first-request failure/hang in production.
#
# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
# DIGEST-PIN REMINDER: python:3.14-slim below is pinned by tag, not by
# @sha256 digest. A specific current digest could not be verified from this
# offline environment, and this project explicitly forbids fabricating
# hashes (see the sibling installer-hardening deliverable's honesty rules)
# -- so this stays tag-pinned rather than shipping a made-up digest. Before
# a real deploy, resolve the tag once (`docker pull python:3.14-slim &&
# docker inspect --format='{{index .RepoDigests 0}}' python:3.14-slim`) and
# replace the tag below with `python:3.14-slim@sha256:<digest>` so the base
# image can't silently change under you between builds.
FROM python:3.14-slim AS builder

# Pin a specific uv release (project requires uv >=0.11.16; see
# scripts/install.sh MIN_UV_VERSION) by copying the static binaries out of
# Astral's official uv-only image. We deliberately do NOT use a combined
# "uv:<ver>-python3.14-*" tag here: at the time this file was written we
# could not verify from this environment which combined tags exist for
# Python 3.14, so we pin uv's version explicitly against a plain python
# base instead of guessing an image tag. Bump UV_VERSION as needed.
#
# Same digest-pin reminder as above applies to this image too: resolve
# `ghcr.io/astral-sh/uv:${UV_VERSION}` to a digest
# (`docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/astral-sh/uv:0.11.16`
# after pulling it) and pin `@sha256:<digest>` before a real deploy. Not
# done here for the same reason: no fabricated digests.
ARG UV_VERSION=0.11.16
COPY --from=ghcr.io/astral-sh/uv:${UV_VERSION} /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache

WORKDIR /build

# Install dependencies first, in their own layer, before the app source is
# copied in -- keeps the dependency layer cache-friendly across source edits.
# --no-dev: exclude the pytest/ruff/ty dev dependency-group.
# --no-editable: install a real wheel into the venv, not a path/editable
#   link back into /build (the builder stage's filesystem won't exist in
#   the runtime image).
# Optional extras ("voice", "voice_local" -- torch/transformers/riva) are
# NOT installed; the proxy server itself does not require them.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev --no-editable

# Now copy the actual application source and install the project itself
# into the same venv.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# Warm the tiktoken BPE cache at build time (network is available here;
# it deliberately is NOT available to the running container -- see
# docker-compose.yml). If this step's egress needs are ever a concern in a
# locked-down build environment, it can be dropped; the app will then fetch
# cl100k_base from openaipublic.blob.core.windows.net on first request
# instead, which requires adding that host to egress/allowed-domains.txt.
RUN /opt/venv/bin/python -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
# Same digest-pin reminder as the builder stage's python:3.14-slim: pin to
# @sha256:<digest> before a real deploy, once you've resolved it yourself.
FROM python:3.14-slim AS runtime

# Fixed, non-root uid/gid (not allocated from the dynamic system range) so
# the same numeric id is stable across rebuilds and matches the `user:`
# override in docker-compose.yml.
ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid "${APP_GID}" fcc \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" \
         --home-dir /home/fcc --no-create-home --shell /usr/sbin/nologin fcc \
    # /home/fcc backs Path.home()/".fcc" (logs, session state, credential
    # cache, lock files -- see config/paths.py). It's created here so the
    # directory exists with correct ownership even before the tmpfs mount
    # from docker-compose.yml is layered over it at container start.
    && mkdir -p /home/fcc \
    && chown "${APP_UID}:${APP_GID}" /home/fcc

# Only the prebuilt venv (deps + the installed free-claude-code wheel) is
# copied in. Application source is NOT copied separately: it was installed
# --no-editable, so the real code already lives inside
# /opt/venv/lib/python3.14/site-packages -- copying src/ again would just be
# a dead, unused duplicate.
COPY --from=builder --chown=${APP_UID}:${APP_GID} /opt/venv /opt/venv
COPY --from=builder --chown=${APP_UID}:${APP_GID} /opt/tiktoken-cache /opt/tiktoken-cache

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache \
    HOME=/home/fcc \
    HOST=0.0.0.0 \
    PORT=8082

WORKDIR /home/fcc

USER ${APP_UID}:${APP_GID}

EXPOSE 8082

# Uses the stdlib (no curl/wget installed in this image on purpose) against
# the real, unauthenticated liveness route registered in api/routes.py.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8082/health', timeout=2).read()" || exit 1

# Matches the [project.scripts] console entry point; binds 0.0.0.0:8082 by
# default per settings.py (HOST/PORT env vars above make that explicit
# rather than relying on the library default).
CMD ["fcc-server"]
