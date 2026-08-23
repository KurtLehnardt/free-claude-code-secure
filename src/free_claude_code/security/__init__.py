"""Default-on security surface for the Claude Code launchers.

Free Claude Code routes a coding agent's model traffic through third-party
providers that FCC does not control. Anything a provider returns can be
interpreted by Claude Code as instructions, including tool calls. The managed
path runs Claude Code with ``--dangerously-skip-permissions``, so nothing asks
a human before a provider-steered tool call executes.

This package supplies a ``PreToolUse`` guard (``hook_guard``) plus the settings
wiring (``hook_settings``) that registers it by default on every FCC Claude Code
launch. It is a heuristic backstop, not the security boundary -- see
``hardening/README.md`` for the threat model and its honest limits.
"""
