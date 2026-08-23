"""Request-body size cap on the inference routes (memory-DoS guard)."""

from typing import cast
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.types import Message, Scope

from free_claude_code.config.settings import Settings
from tests.api.support import create_test_app


def _payload(content: str) -> dict[str, object]:
    return {
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": content}],
    }


def _chunked_inference_scope(path: str) -> Scope:
    """An HTTP scope with no ``content-length`` header (chunked/unknown length)."""
    return cast(
        Scope,
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"content-type", b"application/json"),
            ],
            "client": None,
            "server": None,
        },
    )


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


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/messages", "/v1/responses"])
async def test_oversized_chunked_body_is_rejected_with_413(path: str) -> None:
    """A chunked (no declared Content-Length) over-cap body must still 413.

    /v1/messages and /v1/responses are owned by InferenceRequestLifetimeMiddleware,
    which sits between BodySizeLimitMiddleware and Starlette's ExceptionMiddleware.
    It re-raises whatever its body-receiving task raises, so RequestBodyTooLarge can
    escape past ExceptionMiddleware and previously surfaced as a generic 500 instead
    of the intended 413. Drive the raw ASGI app directly (bypassing TestClient, which
    always sets Content-Length for a plain body) with a body split across multiple
    `http.request` messages whose combined size crosses the cap.
    """
    app = create_test_app(
        Settings(max_request_body_bytes=1024, proxy_auth_enabled=False)
    )
    scope = _chunked_inference_scope(path)
    chunks = iter([(b"x" * 700, True), (b"x" * 700, False)])

    async def receive() -> Message:
        chunk = next(chunks, None)
        if chunk is None:
            return {"type": "http.disconnect"}
        body, more_body = chunk
        return {"type": "http.request", "body": body, "more_body": more_body}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413
    body = b"".join(
        cast(bytes, m.get("body", b""))
        for m in sent
        if m["type"] == "http.response.body"
    )
    assert b"invalid_request_error" in body
    assert b"Request body exceeds the configured maximum size." in body
