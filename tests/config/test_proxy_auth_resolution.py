"""The loader resolves the public-default proxy token to a persisted secret.

The autouse ``_isolate_managed_config`` fixture (see tests/conftest.py) points
``~/.fcc`` at a temp dir, so these exercise the real generation/persistence path
without touching the developer's home directory.
"""

import pytest

from free_claude_code.config.loader import (
    clear_settings_cache,
    compose_settings_snapshot,
    get_settings,
    resolve_settings_snapshot,
)
from free_claude_code.config.paths import proxy_auth_token_path
from free_claude_code.config.proxy_auth import is_public_default_proxy_token


def test_compose_snapshot_keeps_the_public_default_token() -> None:
    # The pure composition layer must not perform token I/O.
    snapshot = compose_settings_snapshot({}, {"ANTHROPIC_AUTH_TOKEN": ""})

    assert snapshot.settings.proxy_auth_token == "freecc"


def test_resolve_snapshot_generates_and_persists_a_secret() -> None:
    # conftest sets ANTHROPIC_AUTH_TOKEN="" in the process environment.
    snapshot = resolve_settings_snapshot()

    token = snapshot.settings.proxy_auth_token
    assert not is_public_default_proxy_token(token)
    assert proxy_auth_token_path().is_file()
    assert proxy_auth_token_path().read_text(encoding="utf-8").strip() == token


def test_resolve_snapshot_preserves_an_explicit_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "my-own-token")

    snapshot = resolve_settings_snapshot()

    assert snapshot.settings.proxy_auth_token == "my-own-token"
    # An explicit token must not trigger generation.
    assert not proxy_auth_token_path().is_file()


def test_server_and_launcher_observe_the_same_generated_token() -> None:
    # First resolution (e.g. fcc-server) generates and persists the token.
    server_token = get_settings().proxy_auth_token
    # A fresh resolution (e.g. a separately-launched fcc-claude process) must read
    # the same persisted value with zero manual setup.
    clear_settings_cache()
    launcher_token = get_settings().proxy_auth_token

    assert server_token == launcher_token
    assert not is_public_default_proxy_token(server_token)
