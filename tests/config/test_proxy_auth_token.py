"""Secure generation and persistence of the proxy auth token."""

import os
import stat
from pathlib import Path

import pytest

from free_claude_code.config.proxy_auth import (
    PUBLIC_DEFAULT_PROXY_AUTH_TOKEN,
    is_public_default_proxy_token,
    load_or_create_proxy_auth_token,
)


@pytest.mark.parametrize("token", ["", "  ", "freecc", "  freecc  "])
def test_public_default_tokens_are_detected(token: str) -> None:
    assert is_public_default_proxy_token(token) is True


@pytest.mark.parametrize("token", ["s3cr3t", "freecc-but-different", "xfreeccx"])
def test_real_tokens_are_not_public_default(token: str) -> None:
    assert is_public_default_proxy_token(token) is False


def test_generates_persists_and_returns_strong_token(tmp_path: Path) -> None:
    token_path = tmp_path / ".fcc" / "proxy_auth_token"

    token = load_or_create_proxy_auth_token(token_path)

    assert token
    assert not is_public_default_proxy_token(token)
    assert token != PUBLIC_DEFAULT_PROXY_AUTH_TOKEN
    assert token_path.read_text(encoding="utf-8").strip() == token


def test_reuses_the_same_token_on_subsequent_calls(tmp_path: Path) -> None:
    token_path = tmp_path / ".fcc" / "proxy_auth_token"

    first = load_or_create_proxy_auth_token(token_path)
    second = load_or_create_proxy_auth_token(token_path)

    assert first == second


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_token_file_and_directory_have_owner_only_permissions(tmp_path: Path) -> None:
    token_path = tmp_path / ".fcc" / "proxy_auth_token"

    load_or_create_proxy_auth_token(token_path)

    file_mode = stat.S_IMODE(token_path.stat().st_mode)
    dir_mode = stat.S_IMODE(token_path.parent.stat().st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700
