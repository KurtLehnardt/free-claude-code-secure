"""Shared filesystem paths for Free Claude Code configuration."""

import contextlib
import os
from pathlib import Path

FCC_CONFIG_DIRNAME = ".fcc"
FCC_ENV_FILENAME = ".env"
LEGACY_REPO_DIRNAME = "free-claude-code"
LEGACY_XDG_CONFIG_DIRNAME = ".config"
MESSAGING_STATE_DIRNAME = "agent_workspace"
FCC_LOGS_DIRNAME = "logs"
SERVER_LOG_FILENAME = "server.log"
PROXY_AUTH_TOKEN_FILENAME = "proxy_auth_token"  # noqa: S105  # filename, not a secret value
CODEX_MODEL_CATALOG_FILENAME = "codex-model-catalog.json"
AUTH_DIRNAME = "auth"
OPENAI_AUTH_FILENAME = "openai.json"
OPENAI_AUTH_LOCK_FILENAME = "openai.lock"
CONFIG_LOCK_FILENAME = "config.lock"


def config_dir_path() -> Path:
    """Return the default user config directory."""

    return Path.home() / FCC_CONFIG_DIRNAME


def ensure_config_dir() -> Path:
    """Create and return ``~/.fcc`` with owner-only (0700) permissions."""

    directory = config_dir_path()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            directory.chmod(0o700)
    return directory


def proxy_auth_token_path() -> Path:
    """Return the persisted, auto-generated proxy auth token path."""

    return config_dir_path() / PROXY_AUTH_TOKEN_FILENAME


def managed_env_path() -> Path:
    """Return the default user-managed env file path."""

    return config_dir_path() / FCC_ENV_FILENAME


def config_lock_path() -> Path:
    """Return the cross-process managed-config migration lock path."""

    return config_dir_path() / CONFIG_LOCK_FILENAME


def legacy_env_paths() -> tuple[Path, ...]:
    """Return legacy user env paths that can be migrated to ~/.fcc/.env."""

    home = Path.home()
    return (
        home / LEGACY_REPO_DIRNAME / FCC_ENV_FILENAME,
        home / LEGACY_XDG_CONFIG_DIRNAME / LEGACY_REPO_DIRNAME / FCC_ENV_FILENAME,
    )


def messaging_state_dir_path() -> Path:
    """Return the managed messaging state directory."""

    return config_dir_path() / MESSAGING_STATE_DIRNAME


def server_log_path() -> Path:
    """Return the canonical server log path."""

    return config_dir_path() / FCC_LOGS_DIRNAME / SERVER_LOG_FILENAME


def codex_model_catalog_path() -> Path:
    """Return the generated Codex model catalog path."""

    return config_dir_path() / CODEX_MODEL_CATALOG_FILENAME


def openai_auth_path() -> Path:
    """Return FCC's private ChatGPT credential file path."""

    return config_dir_path() / AUTH_DIRNAME / OPENAI_AUTH_FILENAME


def openai_auth_lock_path() -> Path:
    """Return the cross-process lock path for ChatGPT credentials."""

    return config_dir_path() / AUTH_DIRNAME / OPENAI_AUTH_LOCK_FILENAME
