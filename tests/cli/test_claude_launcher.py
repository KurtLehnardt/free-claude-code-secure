"""Contract tests for the installed `fcc-claude` launcher command builder."""

import json

from free_claude_code.cli.launchers.claude import build_claude_launcher_command


def test_launcher_registers_security_hook_by_default() -> None:
    command = build_claude_launcher_command(
        binary_path="/usr/bin/claude",
        argv=["--continue"],
        env={"PATH": "keep"},
    )

    assert command[0] == "/usr/bin/claude"
    assert "--settings" in command
    settings_index = command.index("--settings")
    settings = json.loads(command[settings_index + 1])
    assert "PreToolUse" in settings["hooks"]
    # User arguments are preserved and follow the injected settings.
    assert command[-1] == "--continue"


def test_launcher_omits_security_hook_on_opt_out() -> None:
    command = build_claude_launcher_command(
        binary_path="/usr/bin/claude",
        argv=["--continue"],
        env={"FCC_DISABLE_SECURITY_HOOKS": "1"},
    )

    assert command == ["/usr/bin/claude", "--continue"]


def test_launcher_preserves_bare_invocation() -> None:
    command = build_claude_launcher_command(
        binary_path="/usr/bin/claude",
        argv=[],
        env={"FCC_DISABLE_SECURITY_HOOKS": "yes"},
    )

    assert command == ["/usr/bin/claude"]
