"""Request-body size cap on the inference routes (memory-DoS guard)."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from free_claude_code.config.settings import Settings
from tests.api.support import create_test_app


def _payload(content: str) -> dict[str, object]:
    return {
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": content}],
    }


def test_oversized_body_is_rejected_with_413() -> None:
    app = create_test_app(
        Settings(max_request_body_bytes=1024, proxy_auth_enabled=False)
    )
    client = TestClient(app)

    response = client.post("/v1/messages/count_tokens", json=_payload("x" * 8192))

    assert response.status_code == 413


def test_body_within_limit_is_processed() -> None:
    app = create_test_app(Settings(proxy_auth_enabled=False))
    client = TestClient(app)

    with patch("free_claude_code.api.routes.get_token_count", return_value=5):
        response = client.post("/v1/messages/count_tokens", json=_payload("hello"))

    assert response.status_code == 200
    assert response.json()["input_tokens"] == 5


def test_zero_limit_disables_the_cap() -> None:
    app = create_test_app(Settings(max_request_body_bytes=0, proxy_auth_enabled=False))
    client = TestClient(app)

    with patch("free_claude_code.api.routes.get_token_count", return_value=1):
        response = client.post("/v1/messages/count_tokens", json=_payload("y" * 8192))

    assert response.status_code == 200
