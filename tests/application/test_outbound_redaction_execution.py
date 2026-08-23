"""Chokepoint contracts: outbound redaction applied at provider execution.

Both ``/v1/messages`` and ``/v1/responses`` funnel through
``ProviderExecutor.stream`` on the Anthropic-format request before provider
translation, so redaction is verified here once for every wire API.
"""

from collections.abc import AsyncIterator

import pytest

from free_claude_code.application.errors import InvalidRequestError
from free_claude_code.application.execution import ProviderExecutor, WireApi
from free_claude_code.application.routing import (
    ProviderModelTarget,
    ResolvedModelRoute,
    RoutedMessagesRequest,
)
from free_claude_code.config.reasoning import ReasoningPreference
from free_claude_code.core.anthropic.models import Message, MessagesRequest
from free_claude_code.core.failures import ExecutionFailure, FailureKind
from free_claude_code.core.reasoning import ReasoningPolicy
from free_claude_code.core.security import (
    REDACTION_PLACEHOLDER,
    OutboundRedactionMode,
)

# Assembled from parts so the source contains no literal token (push protection).
_SECRET = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz012345"


class RecordingProvider:
    def __init__(self) -> None:
        self.preflight_count = 0
        self.streamed_requests: list[MessagesRequest] = []

    def preflight_stream(
        self, request: MessagesRequest, *, reasoning: ReasoningPolicy
    ) -> None:
        self.preflight_count += 1

    async def stream_response(
        self,
        request: MessagesRequest,
        input_tokens: int = 0,
        *,
        request_id: str | None = None,
        response_model: str | None = None,
        reasoning: ReasoningPolicy,
    ) -> AsyncIterator[str]:
        self.streamed_requests.append(request)
        yield "event: message_stop\ndata: {}\n\n"


def _target(provider_id: str, provider_model: str) -> ProviderModelTarget:
    return ProviderModelTarget(
        provider_id=provider_id,
        provider_model=provider_model,
        provider_model_ref=f"{provider_id}/{provider_model}",
    )


def _routed(content: str, *fallbacks: ProviderModelTarget) -> RoutedMessagesRequest:
    request = MessagesRequest(
        model="provider-model",
        messages=[Message(role="user", content=content)],
    )
    return RoutedMessagesRequest(
        request=request,
        resolved=ResolvedModelRoute(
            original_model="gateway-model",
            primary=_target("provider", "provider-model"),
            fallbacks=fallbacks,
            reasoning_preference=ReasoningPreference.CLIENT,
        ),
        reasoning=ReasoningPolicy.on(),
    )


def _executor(
    provider: RecordingProvider, mode: OutboundRedactionMode
) -> ProviderExecutor:
    return ProviderExecutor(
        lambda _provider_id: provider,
        progress_timeout_seconds=60.0,
        token_counter=lambda _messages, _system, _tools: 5,
        outbound_secret_redaction=mode,
    )


async def _drain(stream: AsyncIterator[str]) -> list[str]:
    return [chunk async for chunk in stream]


@pytest.mark.parametrize("wire_api", ["messages", "responses"])
@pytest.mark.asyncio
async def test_redact_mode_scrubs_secret_from_provider_bound_request(
    wire_api: WireApi,
) -> None:
    provider = RecordingProvider()
    executor = _executor(provider, OutboundRedactionMode.REDACT)
    routed = _routed(f"leaked {_SECRET} here")

    await _drain(
        executor.stream(
            routed,
            wire_api=wire_api,
            raw_log_label="FULL_PAYLOAD",
            raw_log_payload={},
            request_id="req_redact",
        )
    )

    sent = provider.streamed_requests[0].messages[0].content
    assert isinstance(sent, str)
    assert _SECRET not in sent
    assert REDACTION_PLACEHOLDER in sent
    # The caller's routed request is never mutated in place.
    assert routed.request.messages[0].content == f"leaked {_SECRET} here"


class FailingPrimaryProvider(RecordingProvider):
    async def stream_response(
        self,
        request: MessagesRequest,
        input_tokens: int = 0,
        *,
        request_id: str | None = None,
        response_model: str | None = None,
        reasoning: ReasoningPolicy,
    ) -> AsyncIterator[str]:
        self.streamed_requests.append(request)
        if request.messages:  # always true; keeps this a generator function
            raise ExecutionFailure(
                kind=FailureKind.OVERLOADED,
                status_code=529,
                message="overloaded",
                retryable=True,
            )
        yield ""  # unreachable, marks the function as an async generator


@pytest.mark.asyncio
async def test_redact_mode_applies_to_fallback_candidates_too() -> None:
    primary = FailingPrimaryProvider()
    fallback = RecordingProvider()
    providers: dict[str, RecordingProvider] = {
        "provider": primary,
        "fallback": fallback,
    }
    executor = ProviderExecutor(
        providers.__getitem__,
        progress_timeout_seconds=60.0,
        outbound_secret_redaction=OutboundRedactionMode.REDACT,
    )

    await _drain(
        executor.stream(
            _routed(f"leaked {_SECRET}", _target("fallback", "fallback-model")),
            wire_api="messages",
            raw_log_label="FULL_PAYLOAD",
            raw_log_payload={},
            request_id="req_redact_fallback",
        )
    )

    fallback_sent = fallback.streamed_requests[0].messages[0].content
    assert isinstance(fallback_sent, str)
    assert _SECRET not in fallback_sent
    assert REDACTION_PLACEHOLDER in fallback_sent


@pytest.mark.parametrize("wire_api", ["messages", "responses"])
def test_block_mode_rejects_before_any_provider_contact(wire_api: WireApi) -> None:
    provider = RecordingProvider()
    executor = _executor(provider, OutboundRedactionMode.BLOCK)

    with pytest.raises(InvalidRequestError) as exc_info:
        executor.stream(
            _routed(f"leaked {_SECRET}"),
            wire_api=wire_api,
            raw_log_label="FULL_PAYLOAD",
            raw_log_payload={},
            request_id="req_block",
        )

    message = str(exc_info.value)
    assert "outbound secret redaction policy" in message
    assert "anthropic_api_key=1" in message
    assert _SECRET not in message  # never echo the secret
    assert provider.preflight_count == 0
    assert provider.streamed_requests == []


def test_block_mode_allows_clean_request_through() -> None:
    provider = RecordingProvider()
    executor = _executor(provider, OutboundRedactionMode.BLOCK)

    # No secret -> stream() must not raise and must preflight normally.
    executor.stream(
        _routed("an ordinary prompt with no secrets"),
        wire_api="messages",
        raw_log_label="FULL_PAYLOAD",
        raw_log_payload={},
        request_id="req_block_clean",
    )

    assert provider.preflight_count == 1


@pytest.mark.asyncio
async def test_off_mode_passes_secret_through_unchanged() -> None:
    provider = RecordingProvider()
    executor = _executor(provider, OutboundRedactionMode.OFF)

    await _drain(
        executor.stream(
            _routed(f"leaked {_SECRET}"),
            wire_api="messages",
            raw_log_label="FULL_PAYLOAD",
            raw_log_payload={},
            request_id="req_off",
        )
    )

    sent = provider.streamed_requests[0].messages[0].content
    assert sent == f"leaked {_SECRET}"


@pytest.mark.asyncio
async def test_redaction_logs_count_and_category_but_never_the_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = RecordingProvider()
    executor = _executor(provider, OutboundRedactionMode.REDACT)

    with caplog.at_level("WARNING"):
        await _drain(
            executor.stream(
                _routed(f"leaked {_SECRET}"),
                wire_api="messages",
                raw_log_label="FULL_PAYLOAD",
                raw_log_payload={},
                request_id="req_log_safety",
            )
        )

    assert _SECRET not in caplog.text
    assert "redacted 1 secret" in caplog.text
    assert "anthropic_api_key=1" in caplog.text
