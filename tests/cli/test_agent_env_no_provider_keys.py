"""Every launcher must strip provider credentials from the coding agent's env.

Only ``fcc-server`` calls providers. The coding agent subprocess a launcher
spawns (Claude Code, Codex, Pi, OpenCode, Cline, Hermes, DeepSeek Harness,
Grok Build, Muse Code) never needs a provider API key, and a provider-steered
tool call (e.g. a shell command reading its own environment) must not be able
to harvest one. These tests build a base environment containing every
``credential_env`` declared in ``config/provider_catalog.py`` and assert that
none of those real credential values survive into the environment each
launcher hands to its child process.
"""

from pathlib import Path

from free_claude_code.cli.launchers.model_catalog import ClientModel
from free_claude_code.config.provider_catalog import provider_credential_env_names

_LEAK_PREFIX = "LEAKED-"
_PROXY_ROOT_URL = "http://127.0.0.1:9191"
_PROXY_AUTH_TOKEN = "proxy-token"
_AUTO_COMPACT_WINDOW = 190_000


def _provider_credential_env_sample() -> dict[str, str]:
    """Return every catalog credential env name mapped to a leak sentinel."""

    return {name: f"{_LEAK_PREFIX}{name}" for name in provider_credential_env_names()}


def _base_env() -> dict[str, str]:
    return {"PATH": "keep", **_provider_credential_env_sample()}


def _assert_no_provider_credentials_leaked(env: dict[str, str]) -> None:
    """Assert no real credential value from the catalog survives in ``env``.

    A launcher may legitimately keep a provider credential's env var *name*
    (e.g. grok reuses ``XAI_API_KEY``) to carry its own FCC proxy token, so
    this checks values, not just key membership: the important property is
    that the real secret never reaches the child process.
    """

    for name, leaked_value in _provider_credential_env_sample().items():
        assert env.get(name) != leaked_value, (
            f"provider credential {name} leaked into the child agent env"
        )


def test_provider_credential_env_names_covers_named_examples() -> None:
    names = provider_credential_env_names()

    assert {"GROQ_API_KEY", "NVIDIA_NIM_API_KEY", "OPENROUTER_API_KEY"} <= names
    assert isinstance(names, frozenset)


def test_claude_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.claude_env import build_claude_proxy_env

    base_env = _base_env()
    env = build_claude_proxy_env(
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        base_env=base_env,
        auto_compact_window=_AUTO_COMPACT_WINDOW,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["ANTHROPIC_BASE_URL"] == _PROXY_ROOT_URL
    assert env["ANTHROPIC_AUTH_TOKEN"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_codex_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.launchers.codex import build_codex_launcher_env

    base_env = _base_env()
    env = build_codex_launcher_env(
        proxy_root_url=_PROXY_ROOT_URL,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["PATH"] == "keep"


def test_pi_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.launchers.pi import build_pi_launcher_env

    base_env = _base_env()
    env = build_pi_launcher_env(
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["FCC_PI_BASE_URL"] == _PROXY_ROOT_URL
    assert env["FCC_PI_API_KEY"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_opencode_launcher_env_strips_provider_credentials(tmp_path: Path) -> None:
    from free_claude_code.cli.launchers.opencode import build_opencode_launcher_env

    base_env = _base_env()
    env = build_opencode_launcher_env(
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        config_path=tmp_path / "opencode.json",
        overlay={},
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["FCC_OPENCODE_API_KEY"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_cline_launcher_env_strips_provider_credentials(tmp_path: Path) -> None:
    from free_claude_code.cli.launchers.cline import build_cline_launcher_env

    base_env = _base_env()
    env = build_cline_launcher_env(
        proxy_root_url=_PROXY_ROOT_URL,
        providers_path=tmp_path / "providers.json",
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["CLINE_SESSION_BACKEND_MODE"] == "local"
    assert env["PATH"] == "keep"


def test_dsh_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.launchers.dsh import build_dsh_launcher_env

    base_env = _base_env()
    env = build_dsh_launcher_env(
        auth_token=_PROXY_AUTH_TOKEN,
        proxy_root_url=_PROXY_ROOT_URL,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["FCC_DSH_API_KEY"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_hermes_launcher_env_strips_provider_credentials(tmp_path: Path) -> None:
    from free_claude_code.cli.launchers.hermes import build_hermes_launcher_env

    base_env = _base_env()
    env = build_hermes_launcher_env(
        managed_directory=tmp_path,
        key_env="FCC_HERMES_FRESH",
        auth_token=_PROXY_AUTH_TOKEN,
        proxy_root_url=_PROXY_ROOT_URL,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["FCC_HERMES_FRESH"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_grok_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.launchers.grok import build_grok_launcher_env

    models = (
        ClientModel(
            wire_slug="nvidia_nim/vendor/model",
            provider_model_ref="nvidia_nim/vendor/model",
            display_name="Test model",
            allows_reasoning=False,
        ),
    )
    base_env = _base_env()
    env = build_grok_launcher_env(
        models=models,
        selected_model="nvidia_nim/vendor/model",
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    # Grok Build natively reads its API key from XAI_API_KEY, so fcc-grok
    # repurposes that same env var name to carry the FCC proxy token instead
    # of stripping it outright -- the real xAI credential must not survive.
    assert env["XAI_API_KEY"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_muse_launcher_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.launchers.muse import build_muse_launcher_env

    base_env = _base_env()
    env = build_muse_launcher_env(
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        base_env=base_env,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["META_API_KEY"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"


def test_managed_claude_env_strips_provider_credentials() -> None:
    from free_claude_code.cli.managed.claude import build_managed_claude_env

    base_env = _base_env()
    env = build_managed_claude_env(
        proxy_root_url=_PROXY_ROOT_URL,
        auth_token=_PROXY_AUTH_TOKEN,
        base_env=base_env,
        auto_compact_window=_AUTO_COMPACT_WINDOW,
    )

    _assert_no_provider_credentials_leaked(env)
    assert env["ANTHROPIC_BASE_URL"] == _PROXY_ROOT_URL
    assert env["ANTHROPIC_AUTH_TOKEN"] == _PROXY_AUTH_TOKEN
    assert env["PATH"] == "keep"
