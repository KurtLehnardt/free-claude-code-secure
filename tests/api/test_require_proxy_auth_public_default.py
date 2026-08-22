"""A publicly-known default token is never enforced as a real credential."""

import pytest
from fastapi import HTTPException, Request

from free_claude_code.api.dependencies import require_proxy_auth
from free_claude_code.config.settings import Settings


def _request(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (key.lower().encode(), value.encode())
                for key, value in headers.items()
            ],
        }
    )


def test_public_default_token_is_not_enforced_when_missing_header() -> None:
    settings = Settings.model_construct(
        proxy_auth_enabled=True, proxy_auth_token="freecc"
    )

    # No exception: enforcing a public value provides no security.
    require_proxy_auth(_request({}), settings)


def test_public_default_token_ignores_wrong_bearer() -> None:
    settings = Settings.model_construct(
        proxy_auth_enabled=True, proxy_auth_token="freecc"
    )

    require_proxy_auth(_request({"authorization": "Bearer anything"}), settings)


def test_generated_token_is_still_enforced() -> None:
    settings = Settings.model_construct(
        proxy_auth_enabled=True, proxy_auth_token="a-real-generated-secret"
    )

    with pytest.raises(HTTPException) as exc_info:
        require_proxy_auth(_request({}), settings)

    assert exc_info.value.status_code == 401
