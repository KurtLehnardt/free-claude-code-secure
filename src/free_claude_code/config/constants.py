"""Shared defaults used by config models and provider adapters."""

# HTTP client connect timeout (seconds). Keep aligned with README.md and .env.example.
HTTP_CONNECT_TIMEOUT_DEFAULT = 10.0

# Anthropic Messages API default when the client omits max_tokens.
ANTHROPIC_DEFAULT_MAX_OUTPUT_TOKENS = 81920

# Claude Code auto-compaction trigger threshold, in tokens
# (CLAUDE_CODE_AUTO_COMPACT_WINDOW). Matches Claude Code's built-in default,
# tuned for 200k-context official models. Override via AUTO_COMPACT_WINDOW for
# small-context models so compaction fires before a hard context-overflow.
AUTO_COMPACT_WINDOW_DEFAULT = 190_000
