"""Default-on wiring that registers ``fcc-hook-guard`` on Claude Code launches.

Claude Code's ``--settings <file-or-json>`` flag loads *additional* settings and
merges them with the user's ``~/.claude`` configuration (it does not replace
it). Passing an inline JSON string that registers a ``PreToolUse`` hook is
therefore a non-destructive way to make the guard on by default for every FCC
Claude Code launch, while leaving the user's own permissions, hooks, and MCP
config intact.

Set ``FCC_DISABLE_SECURITY_HOOKS=1`` to opt out.
"""

import json
import shlex
import shutil
import sys
from collections.abc import Mapping

from free_claude_code.core.json_types import JsonObject

SECURITY_HOOKS_OPT_OUT_ENV = "FCC_DISABLE_SECURITY_HOOKS"

_GUARD_CONSOLE_SCRIPT = "fcc-hook-guard"
_GUARD_MODULE = "free_claude_code.security.hook_guard"
# Every Claude Code tool that can read a secret, write persistence, fetch a URL,
# or run a shell command. Anything not listed here is out of the guard's reach.
_HOOK_MATCHER = (
    "Bash|Read|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch|Grep|Glob"
)
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def security_hooks_enabled(env: Mapping[str, str]) -> bool:
    """Return True unless ``FCC_DISABLE_SECURITY_HOOKS`` is set truthy."""

    return env.get(SECURITY_HOOKS_OPT_OUT_ENV, "").strip().lower() not in _TRUTHY


def resolve_guard_command() -> str:
    """Return the best command string that invokes the guard.

    Prefers the installed ``fcc-hook-guard`` console script by absolute path so
    the hook resolves regardless of the child process's ``PATH``. Falls back to
    running the module with the current interpreter when the script is not on
    ``PATH`` (e.g. an editable checkout whose scripts are not yet installed).

    Claude Code runs a ``type: command`` hook through a shell, so the path is
    shell-quoted to survive install directories that contain spaces.
    """

    found = shutil.which(_GUARD_CONSOLE_SCRIPT)
    if found:
        return shlex.quote(found)
    return f"{shlex.quote(sys.executable)} -m {_GUARD_MODULE}"


def build_security_settings(command: str | None = None) -> JsonObject:
    """Return the Claude Code settings object that registers the guard hook."""

    hook_command = command if command is not None else resolve_guard_command()
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": _HOOK_MATCHER,
                    "hooks": [{"type": "command", "command": hook_command}],
                }
            ]
        }
    }


def build_security_settings_json(command: str | None = None) -> str:
    """Return the compact JSON string passed to ``claude --settings``."""

    return json.dumps(build_security_settings(command), separators=(",", ":"))


def security_settings_args(env: Mapping[str, str]) -> list[str]:
    """Return ``["--settings", <json>]`` unless the opt-out env var is set."""

    if not security_hooks_enabled(env):
        return []
    return ["--settings", build_security_settings_json()]
