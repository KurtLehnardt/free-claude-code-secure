"""Tests for the default-on security-hook settings wiring."""

import json

from free_claude_code.security.hook_settings import (
    SECURITY_HOOKS_OPT_OUT_ENV,
    build_security_settings,
    build_security_settings_json,
    resolve_guard_command,
    security_hooks_enabled,
    security_settings_args,
)


def test_security_hooks_enabled_by_default() -> None:
    assert security_hooks_enabled({})
    assert security_hooks_enabled({"PATH": "x"})


def test_security_hooks_opt_out_values() -> None:
    for value in ("1", "true", "TRUE", "yes", "on", " On "):
        assert not security_hooks_enabled({SECURITY_HOOKS_OPT_OUT_ENV: value})


def test_security_hooks_ignores_falsey_opt_out() -> None:
    for value in ("", "0", "false", "no", "off"):
        assert security_hooks_enabled({SECURITY_HOOKS_OPT_OUT_ENV: value})


def test_settings_json_is_valid_and_registers_the_hook() -> None:
    settings = json.loads(build_security_settings_json())
    pre_tool_use = settings["hooks"]["PreToolUse"]
    assert isinstance(pre_tool_use, list)
    group = pre_tool_use[0]
    for tool in ("Bash", "Read", "Edit", "Write", "WebFetch", "WebSearch"):
        assert tool in group["matcher"]
    hook = group["hooks"][0]
    assert hook["type"] == "command"
    assert hook["command"]


def test_build_security_settings_accepts_explicit_command() -> None:
    settings = build_security_settings(command="/opt/bin/fcc-hook-guard")
    hooks_config = settings["hooks"]
    assert isinstance(hooks_config, dict)
    pre_tool_use = hooks_config["PreToolUse"]
    assert isinstance(pre_tool_use, list)
    group = pre_tool_use[0]
    assert isinstance(group, dict)
    handlers = group["hooks"]
    assert isinstance(handlers, list)
    handler = handlers[0]
    assert isinstance(handler, dict)
    assert handler["command"] == "/opt/bin/fcc-hook-guard"


def test_resolve_guard_command_returns_runnable_string() -> None:
    command = resolve_guard_command()
    assert command
    assert (
        "fcc-hook-guard" in command or "free_claude_code.security.hook_guard" in command
    )


def test_security_settings_args_default_on() -> None:
    args = security_settings_args({})
    assert args[0] == "--settings"
    settings = json.loads(args[1])
    assert "PreToolUse" in settings["hooks"]


def test_security_settings_args_empty_when_opted_out() -> None:
    assert security_settings_args({SECURITY_HOOKS_OPT_OUT_ENV: "1"}) == []
