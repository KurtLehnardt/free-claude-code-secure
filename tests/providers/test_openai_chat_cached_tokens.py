"""Generic OpenAI-chat prompt-caching (``prompt_tokens_details.cached_tokens``)."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from openai.types.completion_usage import CompletionUsage, PromptTokensDetails

from free_claude_code.core.anthropic import ReasoningReplayMode
from free_claude_code.core.anthropic.models import MessagesRequest
from free_claude_code.core.anthropic.stream_contracts import parse_sse_text
from free_claude_code.core.reasoning import DEFAULT_REASONING_POLICY, ReasoningPolicy
from free_claude_code.providers.openai_chat import (
    OpenAIChatProfile,
    OpenAIChatProvider,
    OpenAIChatRequestPolicy,
)
from free_claude_code.providers.openai_chat.reasoning import NO_REASONING
from free_claude_code.providers.openai_chat.usage import usage_nested_int
from tests.providers.request_factory import make_messages_request
from tests.providers.support import immediate_admission, make_provider_config


class _CachedUsageTestProvider(OpenAIChatProvider):
    """Minimal openai_chat provider exercising the base (unoverridden) path."""

    def __init__(self):
        super().__init__(
            make_provider_config(
                api_key="test_key",
                base_url="https://provider.example/v1",
                rate_limit=100,
                rate_window=60,
            ),
            profile=OpenAIChatProfile(
                OpenAIChatRequestPolicy(
                    provider_name="CACHED_USAGE_TEST",
                    reasoning_replay=ReasoningReplayMode.DISABLED,
                ),
                NO_REASONING,
            ),
            admission=immediate_admission(),
        )

    def _build_request_body(
        self,
        request: MessagesRequest,
        *,
        reasoning: ReasoningPolicy = DEFAULT_REASONING_POLICY,
    ) -> dict:
        return {"model": request.model, "messages": [{"role": "user", "content": "x"}]}


async def _stream(chunks):
    for chunk in chunks:
        yield chunk


def _chunk(*, content=None, finish_reason=None, usage=None):
    if content is None and finish_reason is None:
        return SimpleNamespace(choices=[], usage=usage)
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                delta=SimpleNamespace(
                    content=content,
                    reasoning_content=None,
                    tool_calls=None,
                ),
                finish_reason=finish_reason,
            )
        ],
        usage=usage,
    )


# --- usage_nested_int -------------------------------------------------------


def test_usage_nested_int_reads_dict_of_dicts():
    usage = {"prompt_tokens_details": {"cached_tokens": 800}}
    assert usage_nested_int(usage, "prompt_tokens_details", "cached_tokens") == 800


def test_usage_nested_int_reads_sdk_object_nested_attribute():
    usage = SimpleNamespace(
        prompt_tokens_details=SimpleNamespace(cached_tokens=800),
    )
    assert usage_nested_int(usage, "prompt_tokens_details", "cached_tokens") == 800


def test_usage_nested_int_reads_nested_model_extra():
    """The nested object itself may carry the field via ``model_extra``."""
    nested = SimpleNamespace(model_extra={"cached_tokens": 800})
    usage = SimpleNamespace(prompt_tokens_details=nested)
    assert usage_nested_int(usage, "prompt_tokens_details", "cached_tokens") == 800


def test_usage_nested_int_reads_parent_model_extra():
    """The parent object itself may only carry the nested field via ``model_extra``."""
    usage = SimpleNamespace(
        model_extra={"prompt_tokens_details": {"cached_tokens": 800}}
    )
    assert usage_nested_int(usage, "prompt_tokens_details", "cached_tokens") == 800


def test_usage_nested_int_missing_parent_returns_none():
    assert (
        usage_nested_int(
            {"prompt_tokens": 10}, "prompt_tokens_details", "cached_tokens"
        )
        is None
    )
    assert usage_nested_int(None, "prompt_tokens_details", "cached_tokens") is None


def test_usage_nested_int_real_sdk_types():
    usage = CompletionUsage(
        completion_tokens=50,
        prompt_tokens=1000,
        total_tokens=1050,
        prompt_tokens_details=PromptTokensDetails(cached_tokens=800),
    )
    assert usage_nested_int(usage, "prompt_tokens_details", "cached_tokens") == 800


# --- _anthropic_usage_fields (base openai_chat provider) --------------------


def test_maps_cached_tokens_dict_shape():
    provider = _CachedUsageTestProvider()
    usage = {
        "prompt_tokens": 1000,
        "completion_tokens": 50,
        "prompt_tokens_details": {"cached_tokens": 800},
    }

    assert provider._anthropic_usage_fields(usage) == {
        "input_tokens": 200,
        "cache_read_input_tokens": 800,
    }


def test_maps_cached_tokens_sdk_object_with_model_extra_shape():
    provider = _CachedUsageTestProvider()
    usage = SimpleNamespace(
        prompt_tokens=1000,
        completion_tokens=50,
        model_extra={"prompt_tokens_details": {"cached_tokens": 800}},
    )

    assert provider._anthropic_usage_fields(usage) == {
        "input_tokens": 200,
        "cache_read_input_tokens": 800,
    }


def test_maps_cached_tokens_real_sdk_types():
    provider = _CachedUsageTestProvider()
    usage = CompletionUsage(
        completion_tokens=50,
        prompt_tokens=1000,
        total_tokens=1050,
        prompt_tokens_details=PromptTokensDetails(cached_tokens=800),
    )

    assert provider._anthropic_usage_fields(usage) == {
        "input_tokens": 200,
        "cache_read_input_tokens": 800,
    }


def test_no_prompt_tokens_details_returns_empty_unaffected():
    """NVIDIA NIM/Groq/etc. that don't report caching are unaffected."""
    provider = _CachedUsageTestProvider()
    usage = {"prompt_tokens": 1000, "completion_tokens": 50}

    assert provider._anthropic_usage_fields(usage) == {}


def test_cached_tokens_absent_from_details_returns_empty():
    provider = _CachedUsageTestProvider()
    usage = {
        "prompt_tokens": 1000,
        "completion_tokens": 50,
        "prompt_tokens_details": {},
    }

    assert provider._anthropic_usage_fields(usage) == {}


@pytest.mark.parametrize(
    "usage",
    [
        pytest.param(
            {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": -1},
            },
            id="negative",
        ),
        pytest.param(
            {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": 1001},
            },
            id="exceeds_prompt_tokens",
        ),
        pytest.param(
            {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": 3.5},
            },
            id="non_int_float",
        ),
        pytest.param(
            {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": True},
            },
            id="bool_not_int",
        ),
        pytest.param(
            {
                "prompt_tokens": None,
                "prompt_tokens_details": {"cached_tokens": 10},
            },
            id="missing_prompt_tokens",
        ),
    ],
)
def test_guard_cases_return_empty(usage):
    provider = _CachedUsageTestProvider()
    assert provider._anthropic_usage_fields(usage) == {}


def test_cached_tokens_equal_prompt_tokens_is_allowed():
    provider = _CachedUsageTestProvider()
    usage = {
        "prompt_tokens": 1000,
        "prompt_tokens_details": {"cached_tokens": 1000},
    }

    assert provider._anthropic_usage_fields(usage) == {
        "input_tokens": 0,
        "cache_read_input_tokens": 1000,
    }


def test_cached_tokens_zero_is_allowed():
    provider = _CachedUsageTestProvider()
    usage = {
        "prompt_tokens": 1000,
        "prompt_tokens_details": {"cached_tokens": 0},
    }

    assert provider._anthropic_usage_fields(usage) == {
        "input_tokens": 1000,
        "cache_read_input_tokens": 0,
    }


# --- end-to-end stream: no double-counting -----------------------------------


@pytest.mark.asyncio
async def test_stream_reports_cache_read_input_tokens_with_no_double_count():
    provider = _CachedUsageTestProvider()
    request = make_messages_request(model="m")
    usage = SimpleNamespace(
        prompt_tokens=1000,
        completion_tokens=50,
        prompt_tokens_details=SimpleNamespace(cached_tokens=800),
    )
    create = AsyncMock(
        return_value=_stream(
            [
                _chunk(content="hello"),
                _chunk(finish_reason="stop"),
                _chunk(usage=usage),
            ]
        )
    )

    with patch.object(provider._client.chat.completions, "create", create):
        events = [
            event async for event in provider.stream_response(request, input_tokens=7)
        ]

    parsed = parse_sse_text("".join(events))
    final_usage = next(
        event.data["usage"] for event in parsed if event.event == "message_delta"
    )

    assert final_usage == {
        "input_tokens": 200,
        "output_tokens": 50,
        "cache_read_input_tokens": 800,
    }
    # Non-cached input + cache read must equal the true upstream prompt_tokens;
    # no double-counting of the cached portion.
    assert (
        final_usage["input_tokens"] + final_usage["cache_read_input_tokens"]
        == usage.prompt_tokens
    )


@pytest.mark.asyncio
async def test_stream_without_cache_reporting_is_unaffected():
    """Providers that never report caching (e.g. NVIDIA NIM/Groq) see no change."""
    provider = _CachedUsageTestProvider()
    request = make_messages_request(model="m")
    usage = SimpleNamespace(prompt_tokens=1000, completion_tokens=50)
    create = AsyncMock(
        return_value=_stream(
            [
                _chunk(content="hello"),
                _chunk(finish_reason="stop"),
                _chunk(usage=usage),
            ]
        )
    )

    with patch.object(provider._client.chat.completions, "create", create):
        events = [
            event async for event in provider.stream_response(request, input_tokens=7)
        ]

    parsed = parse_sse_text("".join(events))
    final_usage = next(
        event.data["usage"] for event in parsed if event.event == "message_delta"
    )

    assert final_usage == {"input_tokens": 1000, "output_tokens": 50}
    assert "cache_read_input_tokens" not in final_usage
