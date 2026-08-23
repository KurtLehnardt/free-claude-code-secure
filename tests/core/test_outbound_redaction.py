"""Unit contracts for proxy-side outbound secret redaction."""

import pytest

from free_claude_code.core.anthropic.models import (
    ContentBlockText,
    ContentBlockToolResult,
    ContentBlockToolUse,
    Message,
    MessagesRequest,
    SystemContent,
)
from free_claude_code.core.security import (
    REDACTION_PLACEHOLDER,
    OutboundRedactionMode,
    redact_messages_request,
    redact_text,
)


# One representative sample per supported secret category, assembled from a
# prefix + body at runtime so this source file contains no literal token (which
# secret scanners and GitHub push protection flag). The value is only ever
# asserted *absent* from redacted output, never logged.
def _s(prefix: str, body: str) -> str:
    return prefix + body


_SECRET_SAMPLES: dict[str, str] = {
    "pem_private_key": _s(
        "-----BEGIN ",
        "RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA3fabcdef0123456789\nabcdEFGH+/==\n"
        "-----END RSA PRIVATE KEY-----",
    ),
    "anthropic_api_key": _s("sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz012345"),
    "openai_api_key": _s("sk-", "proj-abcdefghijklmnopqrstuvwxyz0123456789"),
    "groq_api_key": _s("gsk_", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
    "github_token": _s("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789AB"),
    "slack_token": _s("xoxb-", "1234567890-abcdefghijklmnopqrst"),
    "aws_access_key_id": _s("AKIA", "IOSFODNN7EXAMPLE"),
    "nvidia_api_key": _s("nvapi-", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
    "google_api_key": _s("AIza", "SyA1234567890abcdefghijklmnopqrstuvw"),
    "gitlab_token": _s("glpat-", "abcdefghijklmnop12345"),
    "digitalocean_token": "dop_v1_" + "a" * 64,
    "jwt": _s(
        "eyJ",
        "hbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
}


@pytest.mark.parametrize(("category", "secret"), sorted(_SECRET_SAMPLES.items()))
def test_each_secret_category_is_scrubbed(category: str, secret: str) -> None:
    text = f"context before {secret} context after"

    outcome = redact_text(text)

    assert secret not in outcome.text
    assert REDACTION_PLACEHOLDER in outcome.text
    assert outcome.total == 1
    assert outcome.category_counts == {category: 1}


def test_bearer_token_preserves_scheme_but_scrubs_token() -> None:
    secret = "abcdefghijklmnopqrstuvwxyz0123456789"
    outcome = redact_text(f"Authorization: Bearer {secret}")

    assert secret not in outcome.text
    assert outcome.text == f"Authorization: Bearer {REDACTION_PLACEHOLDER}"
    assert outcome.category_counts == {"bearer_token": 1}


def test_high_entropy_assignment_is_scrubbed_and_keeps_key_and_quotes() -> None:
    secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY0"
    outcome = redact_text(f'AWS_SECRET_ACCESS_KEY="{secret}"')

    assert secret not in outcome.text
    assert outcome.text == f'AWS_SECRET_ACCESS_KEY="{REDACTION_PLACEHOLDER}"'
    assert outcome.category_counts == {"credential_assignment": 1}


@pytest.mark.parametrize(
    "text",
    [
        "The sky is blue and the password is on the sticky note.",
        "def make_token(): return next_token_value",
        "password = my_variable_name_here",  # no digit -> not high entropy
        "Set the API_KEY environment variable before running.",
        "commit d4e76d9c0ffee1234567890abcdef1234567890ab",  # bare git sha
        "uuid 123e4567-e89b-12d3-a456-426614174000",
        "sklearn and sk_test are ordinary identifiers",
        "See https://example.com/docs for the api key setup guide.",
    ],
)
def test_ordinary_text_is_not_scrubbed_and_is_identical(text: str) -> None:
    outcome = redact_text(text)

    assert outcome.total == 0
    assert outcome.category_counts == {}
    # No allocation / no rewrite: the exact input object is returned.
    assert outcome.text is text


def test_multiple_distinct_secrets_are_counted_per_category() -> None:
    text = " ".join(
        [
            "one",
            _s("sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz012345"),
            "two",
            _s("gsk_", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
            "three",
            _s("gsk_", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzZZZZ"),
        ]
    )

    outcome = redact_text(text)

    assert outcome.category_counts == {"anthropic_api_key": 1, "groq_api_key": 2}
    assert outcome.total == 3
    assert "sk-ant" not in outcome.text
    assert "gsk_" not in outcome.text


def _request(
    *messages: Message, system: str | list[SystemContent] | None = None
) -> MessagesRequest:
    return MessagesRequest(
        model="provider/model", messages=list(messages), system=system
    )


def test_request_without_secrets_returns_identical_object() -> None:
    request = _request(
        Message(role="user", content="just a normal question about pandas"),
        system="you are a helpful assistant",
    )

    result = redact_messages_request(request)

    assert result.total == 0
    assert result.request is request


def test_plain_string_message_content_is_scrubbed() -> None:
    secret = _SECRET_SAMPLES["anthropic_api_key"]
    request = _request(Message(role="user", content=f"my key is {secret}"))

    result = redact_messages_request(request)

    assert result.total == 1
    assert result.request is not request
    content = result.request.messages[0].content
    assert isinstance(content, str)
    assert secret not in content
    assert REDACTION_PLACEHOLDER in content
    # Original request object is never mutated in place.
    assert request.messages[0].content == f"my key is {secret}"


def test_text_block_and_tool_result_string_are_scrubbed() -> None:
    key = _SECRET_SAMPLES["anthropic_api_key"]
    dumped = _SECRET_SAMPLES["groq_api_key"]
    request = _request(
        Message(
            role="user",
            content=[
                ContentBlockText(type="text", text=f"here is {key}"),
                ContentBlockToolResult(
                    type="tool_result",
                    tool_use_id="toolu_1",
                    content=f"env dump GROQ_API_KEY={dumped}",
                ),
            ],
        )
    )

    result = redact_messages_request(request)

    blocks = result.request.messages[0].content
    assert isinstance(blocks, list)
    text_block, tool_block = blocks
    assert isinstance(text_block, ContentBlockText)
    assert key not in text_block.text and REDACTION_PLACEHOLDER in text_block.text
    assert isinstance(tool_block, ContentBlockToolResult)
    assert isinstance(tool_block.content, str)
    assert dumped not in tool_block.content
    assert REDACTION_PLACEHOLDER in tool_block.content
    assert result.total == 2


def test_tool_result_list_of_text_dicts_is_scrubbed_structurally() -> None:
    secret = _SECRET_SAMPLES["aws_access_key_id"]
    request = _request(
        Message(
            role="user",
            content=[
                ContentBlockToolResult(
                    type="tool_result",
                    tool_use_id="toolu_1",
                    content=[
                        {"type": "text", "text": f"key {secret}"},
                        {"type": "image", "source": {"url": "https://x/y.png"}},
                    ],
                )
            ],
        )
    )

    result = redact_messages_request(request)

    tool_block = result.request.messages[0].content[0]
    assert isinstance(tool_block, ContentBlockToolResult)
    items = tool_block.content
    assert isinstance(items, list)
    assert items[0] == {"type": "text", "text": f"key {REDACTION_PLACEHOLDER}"}
    # Non-text structured item is untouched.
    assert items[1] == {"type": "image", "source": {"url": "https://x/y.png"}}
    assert result.total == 1


def test_tool_use_input_is_never_touched() -> None:
    secret = _SECRET_SAMPLES["anthropic_api_key"]
    request = _request(
        Message(
            role="assistant",
            content=[
                ContentBlockToolUse(
                    type="tool_use",
                    id="toolu_1",
                    name="bash",
                    input={"command": f"export KEY={secret}"},
                )
            ],
        )
    )

    result = redact_messages_request(request)

    # tool_use input is structured and intentionally out of scope.
    assert result.total == 0
    assert result.request is request


def test_system_string_and_blocks_are_scrubbed() -> None:
    secret = _SECRET_SAMPLES["nvidia_api_key"]
    request = _request(
        Message(role="user", content="hi"),
        system=[SystemContent(type="text", text=f"deploy token {secret}")],
    )

    result = redact_messages_request(request)

    system = result.request.system
    assert isinstance(system, list)
    assert secret not in system[0].text
    assert REDACTION_PLACEHOLDER in system[0].text
    assert result.total == 1


def test_summary_lists_categories_without_values() -> None:
    request = _request(
        Message(
            role="user",
            content=(
                f"{_SECRET_SAMPLES['anthropic_api_key']} and "
                f"{_SECRET_SAMPLES['aws_access_key_id']}"
            ),
        )
    )

    result = redact_messages_request(request)

    summary = result.summary()
    assert summary == "anthropic_api_key=1, aws_access_key_id=1"
    for secret in _SECRET_SAMPLES.values():
        assert secret not in summary


def test_redaction_modes_are_the_three_documented_values() -> None:
    assert {mode.value for mode in OutboundRedactionMode} == {"off", "redact", "block"}
