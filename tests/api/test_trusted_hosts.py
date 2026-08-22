"""TrustedHostMiddleware Host-header allowlist (DNS-rebinding defense)."""

from fastapi.testclient import TestClient

from free_claude_code.api.app import _resolve_trusted_hosts, create_app
from free_claude_code.config.settings import Settings
from tests.api.support import create_test_app


def test_loopback_bind_allows_loopback_names_and_testclient() -> None:
    hosts = _resolve_trusted_hosts(Settings(host="127.0.0.1"))

    assert "127.0.0.1" in hosts
    assert "localhost" in hosts
    assert "::1" in hosts
    assert "testserver" in hosts
    assert "*" not in hosts


def test_wildcard_bind_without_trusted_hosts_disables_host_checking() -> None:
    assert _resolve_trusted_hosts(Settings(host="0.0.0.0")) == ["*"]


def test_wildcard_bind_with_trusted_hosts_reenables_checking() -> None:
    hosts = _resolve_trusted_hosts(
        Settings(host="0.0.0.0", trusted_hosts="proxy.internal")
    )

    assert "proxy.internal" in hosts
    assert "*" not in hosts


def test_configured_lan_host_is_allowed() -> None:
    hosts = _resolve_trusted_hosts(Settings(host="192.168.1.10"))

    assert "192.168.1.10" in hosts


def test_unknown_host_header_is_rejected() -> None:
    app = create_test_app(Settings(proxy_auth_enabled=False))
    client = TestClient(app)

    response = client.get("/", headers={"host": "attacker.example"})

    assert response.status_code == 400


def test_loopback_host_header_is_accepted() -> None:
    app = create_test_app(Settings(proxy_auth_enabled=False))
    client = TestClient(app)

    response = client.get("/", headers={"host": "127.0.0.1:8082"})

    # Reaches the route (not blocked by the Host allowlist).
    assert response.status_code != 400


def test_create_app_registers_trusted_host_middleware() -> None:
    app = create_test_app(Settings(proxy_auth_enabled=False))

    middleware_classes = {entry.cls.__name__ for entry in app.user_middleware}
    assert "TrustedHostMiddleware" in middleware_classes
    assert "BodySizeLimitMiddleware" in middleware_classes
    assert create_app is not None
