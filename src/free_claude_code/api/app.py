"""Pure FastAPI application factory."""

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.trustedhost import TrustedHostMiddleware

from free_claude_code.application.errors import ApplicationError
from free_claude_code.config.settings import Settings
from free_claude_code.core.anthropic import anthropic_error_payload
from free_claude_code.core.diagnostics import (
    redacted_exception_traceback,
    safe_exception_message,
)
from free_claude_code.core.openai_responses import openai_error_payload
from free_claude_code.core.trace import (
    extract_claude_session_id_from_headers,
    trace_event,
)
from free_claude_code.core.version import package_version

from .admin_cache import AdminNoStoreMiddleware, attach_admin_no_store
from .admin_routes import router as admin_router
from .ports import ApiServices
from .request_errors import ordinary_application_error_response
from .request_ids import (
    RequestCorrelationMiddleware,
    attach_request_id_headers,
    get_request_id,
)
from .request_lifetime import InferenceRequestLifetimeMiddleware
from .request_limits import BodySizeLimitMiddleware, RequestBodyTooLarge
from .routes import router
from .validation_log import summarize_request_validation_body

# httpx/Starlette TestClient sentinel Host. It is not internet-routable, so allowing
# it costs nothing against DNS rebinding while keeping the API testable.
_TESTCLIENT_HOST = "testserver"
_LOOPBACK_HOST_NAMES = ("localhost", "127.0.0.1", "::1")
_WILDCARD_BINDS = frozenset({"", "0.0.0.0", "::"})  # noqa: S104  # sentinels for detecting a wildcard bind, not an actual socket bind


def _resolve_trusted_hosts(settings: Settings) -> list[str]:
    """Return the Host-header allowlist for :class:`TrustedHostMiddleware`.

    Loopback binds get strict validation (the DNS-rebinding case). A deliberate
    all-interfaces bind with no explicit ``TRUSTED_HOSTS`` disables Host checking
    (authentication is the control there); listing hosts re-enables it.
    """

    configured_extra = [
        part.strip().strip("[]").lower()
        for part in (settings.trusted_hosts or "").split(",")
        if part.strip()
    ]
    host = (settings.host or "").strip().strip("[]").lower()
    wildcard_bind = host in _WILDCARD_BINDS
    if wildcard_bind and not configured_extra:
        return ["*"]
    hosts = set(_LOOPBACK_HOST_NAMES)
    hosts.add(_TESTCLIENT_HOST)
    hosts.update(configured_extra)
    if not wildcard_bind and host:
        hosts.add(host)
    return sorted(hosts)


def create_app(services: ApiServices) -> FastAPI:
    """Create the HTTP adapter around explicitly supplied runtime services."""
    app = FastAPI(title="Claude Code Proxy", version=package_version())
    app.state.services = services
    settings = services.requests.current_settings()
    app.add_middleware(AdminNoStoreMiddleware)
    app.add_middleware(InferenceRequestLifetimeMiddleware)
    app.add_middleware(RequestCorrelationMiddleware)
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_body_bytes=settings.max_request_body_bytes,
    )
    # Outermost user middleware: reject spoofed/rebound Host headers before any work.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_resolve_trusted_hosts(settings),
    )

    app.include_router(admin_router)
    app.include_router(router)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        """Log request shape for 422 debugging without content values."""
        body: object
        try:
            body = await request.json()
        except Exception as error:
            body = {"_json_error": type(error).__name__}

        message_summary, tool_names = summarize_request_validation_body(body)
        trace_event(
            stage="ingress",
            event="server.request.validation_failed",
            source="api",
            path=request.url.path,
            query=dict(request.query_params),
            error_locs=[list(error.get("loc", ())) for error in exc.errors()],
            error_types=[str(error.get("type", "")) for error in exc.errors()],
            message_summary=message_summary,
            tool_names=tool_names,
        )
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(RequestBodyTooLarge)
    async def body_too_large_handler(request: Request, exc: RequestBodyTooLarge):
        """Return HTTP 413 for request bodies over the configured cap."""
        request_id = get_request_id(request)
        message = "Request body exceeds the configured maximum size."
        if request.url.path == "/v1/responses":
            content = openai_error_payload(
                message=message, error_type="invalid_request_error"
            )
        else:
            content = anthropic_error_payload(
                error_type="invalid_request_error",
                message=message,
                request_id=request_id,
            )
        response = JSONResponse(status_code=413, content=content)
        attach_admin_no_store(response, path=request.url.path)
        attach_request_id_headers(
            response,
            request_id=request_id,
            path=request.url.path,
        )
        return response

    @app.exception_handler(ApplicationError)
    async def application_error_handler(request: Request, exc: ApplicationError):
        """Serialize defensive application failures in the selected wire protocol."""
        return ordinary_application_error_response(
            exc,
            wire_api=(
                "responses" if request.url.path == "/v1/responses" else "messages"
            ),
            request_id=get_request_id(request),
        )

    @app.exception_handler(Exception)
    async def general_error_handler(request: Request, exc: Exception):
        """Handle general errors and return Anthropic format."""
        request_id = get_request_id(request)
        claude_sid = extract_claude_session_id_from_headers(request.headers)
        settings = services.requests.current_settings()
        with logger.contextualize(
            http_method=request.method,
            http_path=request.url.path,
            claude_session_id=claude_sid,
            request_id=request_id,
        ):
            if settings.log_api_error_tracebacks:
                logger.error("General Error: {}", safe_exception_message(exc))
                logger.error(redacted_exception_traceback(exc))
            else:
                logger.error(
                    "General Error: path={} method={} exc_type={}",
                    request.url.path,
                    request.method,
                    type(exc).__name__,
                )
            message = safe_exception_message(exc)
            if request.url.path == "/v1/responses":
                content = openai_error_payload(message=message, error_type="api_error")
            else:
                content = anthropic_error_payload(
                    error_type="api_error",
                    message=message,
                    request_id=request_id,
                )
            response = JSONResponse(status_code=500, content=content)
        attach_admin_no_store(response, path=request.url.path)
        attach_request_id_headers(
            response,
            request_id=request_id,
            path=request.url.path,
        )
        return response

    return app
