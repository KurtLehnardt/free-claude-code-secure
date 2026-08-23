"""Pattern-based redaction of secrets in provider-bound request content.

This is a proxy-side, outbound mitigation: it scrubs high-signal secret shapes
from the Anthropic-format request *before* that request is translated and sent to
a (potentially untrusted) cloud provider. It reduces accidental leakage of
secrets that ended up in the agent's context -- for example a tool result that
dumped environment variables or a pasted ``.env`` file.

Scope and honest limits:

* It is best-effort and pattern-based. It matches known credential shapes and
  conservative high-entropy assignments. It will NOT catch obfuscated secrets,
  base64-wrapped blobs, or arbitrary proprietary content. It reduces *accidental*
  leakage, it is not a defense against deliberate data exfiltration.
* It only rewrites free-form *text*: plain-string message content, ``text``
  content blocks, ``system`` text, and the textual payload of ``tool_result``
  blocks. It never rewrites structured fields (``tool_use`` inputs, image or
  document sources, thinking signatures) and never changes the JSON/message
  structure, so a redacted request stays wire-valid.

The public surface is SDK-free and deterministic so it can be unit tested in
isolation and reused by any provider path through a single chokepoint.
"""

import math
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from free_claude_code.core.anthropic.models import (
    ContentBlockText,
    ContentBlockToolResult,
    Message,
    MessagesRequest,
    SystemContent,
)

REDACTION_PLACEHOLDER = "[REDACTED-SECRET]"


class OutboundRedactionMode(StrEnum):
    """Policy for handling secrets detected in an outbound request."""

    OFF = "off"
    REDACT = "redact"
    BLOCK = "block"


def _has_alpha(value: str) -> bool:
    return any(char.isalpha() for char in value)


def _has_digit(value: str) -> bool:
    return any(char.isdigit() for char in value)


def _shannon_entropy(value: str) -> float:
    """Bits-per-character Shannon entropy of ``value`` (0.0 for empty)."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_high_entropy_secret(value: str) -> bool:
    """Conservative gate for generic ``KEY = value`` assignments.

    Requires a token-shaped value (mixed letters and digits, no whitespace) with
    enough entropy that it is unlikely to be an ordinary identifier or English
    word. This keeps everyday code such as ``password = my_variable_name`` or
    ``token = next_token`` from being scrubbed.
    """
    if len(value) < 16:
        return False
    if not (_has_alpha(value) and _has_digit(value)):
        return False
    return _shannon_entropy(value) >= 3.0


@dataclass(frozen=True, slots=True)
class _SecretPattern:
    """One named secret shape and how to rebuild the match once redacted.

    When the pattern exposes a ``keep`` named group (e.g. the ``Bearer `` scheme
    or an ``API_KEY=`` prefix), only the ``secret`` group is replaced and the
    surrounding context -- including a captured ``q`` quote group -- is restored.
    Otherwise the whole match is replaced. An optional ``validate`` predicate can
    veto a match (used for the conservative high-entropy assignment gate).
    """

    name: str
    regex: re.Pattern[str]
    validate: Callable[[str], bool] | None = None

    def _target(self, match: re.Match[str]) -> str:
        if "secret" in self.regex.groupindex:
            return match.group("secret")
        return match.group(0)

    def replacement_for(self, match: re.Match[str]) -> str | None:
        """Redacted replacement text, or ``None`` to leave the match untouched."""
        if self.validate is not None and not self.validate(self._target(match)):
            return None
        if "keep" not in self.regex.groupindex:
            return REDACTION_PLACEHOLDER
        keep = match.group("keep")
        quote = match.group("q") if "q" in self.regex.groupindex else ""
        return f"{keep}{quote}{REDACTION_PLACEHOLDER}{quote}"


# High-signal secret shapes. Ordered most-specific first so structured secrets
# (PEM blocks, provider-prefixed keys, JWTs) are consumed before the generic
# assignment fallback runs. Extend this list to cover new credential shapes;
# keep each entry conservative to avoid scrubbing ordinary prose or code.
_SECRET_PATTERNS: tuple[_SecretPattern, ...] = (
    # PEM private keys (RSA/EC/OPENSSH/PGP/generic), including the delimiters.
    _SecretPattern(
        name="pem_private_key",
        regex=re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    # Anthropic API keys (must precede the generic ``sk-`` OpenAI shape).
    _SecretPattern(
        name="anthropic_api_key",
        regex=re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ),
    # OpenAI API keys, incl. project/service/admin variants.
    _SecretPattern(
        name="openai_api_key",
        regex=re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    ),
    # Groq API keys.
    _SecretPattern(
        name="groq_api_key",
        regex=re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    ),
    # GitHub tokens: PAT (ghp_), OAuth (gho_), user (ghu_), server (ghs_), refresh (ghr_).
    _SecretPattern(
        name="github_token",
        regex=re.compile(r"gh[oprsu]_[A-Za-z0-9]{30,}"),
    ),
    # GitHub fine-grained PATs.
    _SecretPattern(
        name="github_token",
        regex=re.compile(r"github_pat_[A-Za-z0-9_]{60,}"),
    ),
    # Slack tokens (bot/app/user/refresh/legacy).
    _SecretPattern(
        name="slack_token",
        regex=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ),
    # AWS access key IDs (the secret access key is caught by the assignment rule).
    _SecretPattern(
        name="aws_access_key_id",
        regex=re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}"),
    ),
    # NVIDIA NIM / build.nvidia.com keys.
    _SecretPattern(
        name="nvidia_api_key",
        regex=re.compile(r"nvapi-[A-Za-z0-9_\-]{20,}"),
    ),
    # Google API keys (Maps, AI Studio/Gemini, etc.).
    _SecretPattern(
        name="google_api_key",
        regex=re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    ),
    # GitLab personal access tokens.
    _SecretPattern(
        name="gitlab_token",
        regex=re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    ),
    # DigitalOcean v1 tokens.
    _SecretPattern(
        name="digitalocean_token",
        regex=re.compile(r"dop_v1_[A-Fa-f0-9]{64}"),
    ),
    # JSON Web Tokens (header.payload.signature).
    _SecretPattern(
        name="jwt",
        regex=re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ),
    # ``Bearer <token>`` with a long opaque token (scheme is preserved).
    _SecretPattern(
        name="bearer_token",
        regex=re.compile(
            r"(?P<keep>(?i:bearer)[ \t]+)(?P<secret>[A-Za-z0-9_\-\.=+/]{20,})"
        ),
    ),
    # Generic ``API_KEY = <high-entropy value>`` assignments. Conservative: the
    # value must pass the high-entropy gate, so ordinary identifiers survive.
    _SecretPattern(
        name="credential_assignment",
        regex=re.compile(
            r"(?P<keep>"
            r"(?i:api[_-]?keys?|secret(?:[_-]?access)?(?:[_-]?key)?|"
            r"access[_-]?key(?:[_-]?id)?|auth[_-]?token|token|"
            r"password|passwd|passphrase|private[_-]?key)"
            r"[\"']?[ \t]*[:=][ \t]*)"
            r"(?P<q>[\"']?)"
            r"(?P<secret>[A-Za-z0-9+/_\-\.=]{16,})"
            r"(?P=q)"
        ),
        validate=_looks_high_entropy_secret,
    ),
)


@dataclass(frozen=True, slots=True)
class TextRedaction:
    """Result of redacting a single text value."""

    text: str
    category_counts: Mapping[str, int]

    @property
    def total(self) -> int:
        return sum(self.category_counts.values())


def redact_text(text: str) -> TextRedaction:
    """Redact every known secret shape in ``text``.

    Returns a :class:`TextRedaction`. When nothing matched, ``text`` is the
    identical input object (no allocation, no false rewrite).
    """
    counts: Counter[str] = Counter()
    current = text
    for pattern in _SECRET_PATTERNS:

        def _substitute(
            match: re.Match[str], _pattern: _SecretPattern = pattern
        ) -> str:
            replacement = _pattern.replacement_for(match)
            if replacement is None:
                return match.group(0)
            counts[_pattern.name] += 1
            return replacement

        current = pattern.regex.sub(_substitute, current)
    if not counts:
        return TextRedaction(text=text, category_counts={})
    return TextRedaction(text=current, category_counts=dict(counts))


def _redact_str(text: str, counts: Counter[str]) -> str:
    outcome = redact_text(text)
    if outcome.total == 0:
        return text
    counts.update(outcome.category_counts)
    return outcome.text


def _redact_tool_result_content(content: object, counts: Counter[str]) -> object:
    """Redact ``tool_result`` payloads without disturbing their structure."""
    if isinstance(content, str):
        return _redact_str(content, counts)
    if isinstance(content, list):
        redacted_items = [_redact_tool_result_item(item, counts) for item in content]
        if all(new is old for new, old in zip(redacted_items, content, strict=True)):
            return content
        return redacted_items
    if isinstance(content, dict):
        return _redact_text_dict(content, counts)
    return content


def _redact_tool_result_item(item: object, counts: Counter[str]) -> object:
    if isinstance(item, str):
        return _redact_str(item, counts)
    if isinstance(item, dict):
        return _redact_text_dict(item, counts)
    return item


def _redact_text_dict(block: Mapping[str, object], counts: Counter[str]) -> object:
    """Redact only the ``text`` of a ``{"type": "text", "text": ...}`` block.

    Any other structured dict is returned unchanged so we never corrupt
    non-text tool-result payloads (e.g. JSON search results).
    """
    if block.get("type") != "text":
        return block
    text = block.get("text")
    if not isinstance(text, str):
        return block
    redacted = _redact_str(text, counts)
    if redacted is text:
        return block
    return {**block, "text": redacted}


def _redact_message(message: Message, counts: Counter[str]) -> Message:
    content = message.content
    if isinstance(content, str):
        redacted = _redact_str(content, counts)
        if redacted is content:
            return message
        return message.model_copy(update={"content": redacted})
    redacted_blocks = [_redact_content_block(block, counts) for block in content]
    if all(new is old for new, old in zip(redacted_blocks, content, strict=True)):
        return message
    return message.model_copy(update={"content": redacted_blocks})


def _redact_content_block(
    block: ContentBlockText | ContentBlockToolResult | object,
    counts: Counter[str],
) -> object:
    if isinstance(block, ContentBlockText):
        redacted = _redact_str(block.text, counts)
        if redacted is block.text:
            return block
        return block.model_copy(update={"text": redacted})
    if isinstance(block, ContentBlockToolResult):
        redacted_content = _redact_tool_result_content(block.content, counts)
        if redacted_content is block.content:
            return block
        return block.model_copy(update={"content": redacted_content})
    return block


def _redact_system(
    system: str | list[SystemContent] | None, counts: Counter[str]
) -> str | list[SystemContent] | None:
    if isinstance(system, str):
        return _redact_str(system, counts)
    if isinstance(system, list):
        redacted = [_redact_system_block(block, counts) for block in system]
        if all(new is old for new, old in zip(redacted, system, strict=True)):
            return system
        return redacted
    return system


def _redact_system_block(block: SystemContent, counts: Counter[str]) -> SystemContent:
    redacted = _redact_str(block.text, counts)
    if redacted is block.text:
        return block
    return block.model_copy(update={"text": redacted})


@dataclass(frozen=True, slots=True)
class RequestRedaction:
    """Result of redacting an outbound :class:`MessagesRequest`."""

    request: MessagesRequest
    category_counts: Mapping[str, int]

    @property
    def total(self) -> int:
        return sum(self.category_counts.values())

    def summary(self) -> str:
        """Human-readable ``name=count`` summary (never includes secret values)."""
        return ", ".join(
            f"{name}={count}" for name, count in sorted(self.category_counts.items())
        )


def redact_messages_request(request: MessagesRequest) -> RequestRedaction:
    """Return a redacted copy of ``request`` plus per-category redaction counts.

    Only text-bearing fields are touched. When nothing matched, the returned
    ``request`` is the identical input object.
    """
    counts: Counter[str] = Counter()
    redacted_system = _redact_system(request.system, counts)
    redacted_messages = [
        _redact_message(message, counts) for message in request.messages
    ]
    if not counts:
        return RequestRedaction(request=request, category_counts={})
    redacted = request.model_copy(
        update={"system": redacted_system, "messages": redacted_messages}
    )
    return RequestRedaction(request=redacted, category_counts=dict(counts))
