"""Proxy authentication token: public-default detection and secure persistence.

The shipped configuration never contains a real secret. When the configured proxy
auth token is unset or the publicly-known default, a cryptographically-random token
is generated once and persisted under ``~/.fcc`` with ``0600`` permissions so that
``fcc-server`` and every launcher (``fcc-claude``/``fcc-codex``/...) read the same
value through :func:`free_claude_code.config.loader.get_settings`.
"""

import contextlib
import os
import secrets
from pathlib import Path

from .paths import proxy_auth_token_path

# Publicly-known placeholder shipped in defaults and documentation. It is never a
# real secret; treat it as "no token configured".
PUBLIC_DEFAULT_PROXY_AUTH_TOKEN = "freecc"

# 32 random bytes -> ~43 character URL-safe token.
_TOKEN_BYTES = 32


def is_public_default_proxy_token(token: str) -> bool:
    """Return True when ``token`` is empty or the publicly-known default."""

    stripped = token.strip()
    return stripped == "" or stripped == PUBLIC_DEFAULT_PROXY_AUTH_TOKEN


def load_or_create_proxy_auth_token(path: Path | None = None) -> str:
    """Return the persisted proxy auth token, generating one on first use.

    The token file and its parent directory are created with owner-only
    permissions. Concurrent creators (e.g. the server and a launcher started at
    the same time) converge on a single value via exclusive-create semantics.
    """

    token_path = path or proxy_auth_token_path()

    existing = _read_token(token_path)
    if existing is not None:
        return existing

    parent = token_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            parent.chmod(0o700)

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    with contextlib.suppress(FileExistsError):
        _create_token_file(token_path, token)

    winner = _read_token(token_path)
    return winner if winner is not None else token


def _read_token(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    token = text.strip()
    return token or None


def _create_token_file(path: Path, token: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
