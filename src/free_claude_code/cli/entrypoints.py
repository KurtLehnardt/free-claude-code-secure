"""Lightweight entry points for installed Free Claude Code commands."""

import sys
from collections.abc import Sequence

from free_claude_code.core.version import package_version


def serve(argv: Sequence[str] | None = None) -> None:
    """Start the FastAPI server (registered as ``fcc-server``)."""
    if _print_version_if_requested(argv):
        return

    # Keep the server composition root off metadata-only command paths.
    from free_claude_code.cli.commands import (
        enforce_exposure_safety,
        log_proxy_auth_token_location,
    )
    from free_claude_code.cli.commands import (
        serve as run_server,
    )
    from free_claude_code.config.loader import get_settings

    settings = get_settings()
    enforce_exposure_safety(settings)
    log_proxy_auth_token_location(settings)
    run_server()


def _print_version_if_requested(argv: Sequence[str] | None) -> bool:
    args = sys.argv[1:] if argv is None else argv
    if "--version" not in args:
        return False
    print(f"free-claude-code {package_version()}")
    return True
