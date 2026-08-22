"""Request-body size enforcement (memory-DoS guard) for the proxy API."""

from collections.abc import Awaitable, Callable, MutableMapping

Scope = MutableMapping[str, object]
Message = MutableMapping[str, object]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_TOO_LARGE_BODY = (
    b'{"type":"error","error":{"type":"invalid_request_error",'
    b'"message":"Request body exceeds the configured maximum size."}}'
)


class RequestBodyTooLarge(Exception):
    """Raised when an incoming request body exceeds the configured cap."""


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_body_bytes`` before buffering them.

    Two layers: a declared ``Content-Length`` over the cap is rejected up front with
    HTTP 413 (the common case; clients set it for JSON bodies). For chunked/unknown-
    length bodies, bytes are counted as chunks arrive and the first chunk that crosses
    the cap raises :class:`RequestBodyTooLarge` from ``receive`` inside the app, so
    nothing beyond the cap is ever accumulated. ``max_body_bytes <= 0`` disables it.
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or self.max_body_bytes <= 0:
            await self.app(scope, receive, send)
            return

        declared = _declared_content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            await _send_too_large(send)
            return

        remaining = self.max_body_bytes

        async def guarded_receive() -> Message:
            nonlocal remaining
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if isinstance(body, (bytes, bytearray)):
                    remaining -= len(body)
                    if remaining < 0:
                        raise RequestBodyTooLarge()
            return message

        await self.app(scope, guarded_receive, send)


def _declared_content_length(scope: Scope) -> int | None:
    headers = scope.get("headers") or []
    if not isinstance(headers, (list, tuple)):
        return None
    for name, value in headers:
        if name == b"content-length":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


async def _send_too_large(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_TOO_LARGE_BODY)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _TOO_LARGE_BODY})
