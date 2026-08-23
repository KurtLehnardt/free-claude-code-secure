"""Fail-safe startup gate: refuse non-loopback exposure without real auth."""

import pytest

from free_claude_code.cli.commands import enforce_exposure_safety
from free_claude_code.config.settings import Settings


def test_loopback_bind_is_always_allowed() -> None:
    enforce_exposure_safety(
        Settings(
            host="127.0.0.1",
            proxy_auth_enabled=False,
            proxy_auth_token="freecc",
        )
    )


def test_localhost_bind_is_allowed() -> None:
    enforce_exposure_safety(
        Settings(host="localhost", proxy_auth_enabled=False, proxy_auth_token="freecc")
    )


def test_non_loopback_without_auth_refuses_to_start() -> None:
    with pytest.raises(SystemExit):
        enforce_exposure_safety(
            Settings(
                host="0.0.0.0",
                proxy_auth_enabled=False,
                proxy_auth_token="strong-token-value",
            )
        )


def test_non_loopback_with_public_default_token_refuses_to_start() -> None:
    with pytest.raises(SystemExit):
        enforce_exposure_safety(
            Settings(
                host="0.0.0.0",
                proxy_auth_enabled=True,
                proxy_auth_token="freecc",
            )
        )


def test_non_loopback_with_auth_and_strong_token_is_allowed() -> None:
    enforce_exposure_safety(
        Settings(
            host="0.0.0.0",
            proxy_auth_enabled=True,
            proxy_auth_token="a-strong-secret-token",
        )
    )
