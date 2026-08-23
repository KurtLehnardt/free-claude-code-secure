"""Admin gate hardening: DNS-rebinding Host allowlist + XFF spoofing defense."""

from fastapi.testclient import TestClient

from free_claude_code.api.admin_routes import _admin_host_header_is_local
from free_claude_code.config.settings import Settings
from tests.api.support import create_test_app


def _loopback_client(app) -> TestClient:
    return TestClient(app, client=("127.0.0.1", 50000))


def test_admin_host_header_helper_accepts_only_local_names() -> None:
    assert _admin_host_header_is_local("127.0.0.1:8082") is True
    assert _admin_host_header_is_local("localhost:8082") is True
    assert _admin_host_header_is_local("[::1]:8082") is True
    assert _admin_host_header_is_local("testserver") is True
    assert _admin_host_header_is_local("attacker.example") is False
    assert _admin_host_header_is_local("attacker.example:8082") is False
    assert _admin_host_header_is_local(None) is False


def test_admin_allows_local_loopback_request() -> None:
    client = _loopback_client(create_test_app())

    response = client.get("/admin/api/config")

    assert response.status_code == 200


def test_admin_rejects_forwarded_for_header() -> None:
    client = _loopback_client(create_test_app())

    response = client.get("/admin/api/config", headers={"X-Forwarded-For": "127.0.0.1"})

    assert response.status_code == 403


def test_admin_rejects_forwarded_header() -> None:
    client = _loopback_client(create_test_app())

    response = client.get("/admin/api/config", headers={"Forwarded": "for=127.0.0.1"})

    assert response.status_code == 403


def test_admin_rejects_rebinding_host_even_when_trusted_host_allows_it() -> None:
    # trusted_hosts lets the Host pass TrustedHostMiddleware, but the admin gate
    # independently requires a loopback Host to defeat DNS rebinding.
    app = create_test_app(Settings(trusted_hosts="rebind.example"))
    client = _loopback_client(app)

    response = client.get("/admin/api/config", headers={"host": "rebind.example"})

    assert response.status_code == 403
