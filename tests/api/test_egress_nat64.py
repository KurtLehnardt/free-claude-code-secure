"""SSRF guard: NAT64/IPv4-embedding IPv6 literals must not reach loopback."""

import pytest

from free_claude_code.api.web_tools.egress import (
    WebFetchEgressPolicy,
    WebFetchEgressViolation,
    enforce_web_fetch_egress,
)

_POLICY = WebFetchEgressPolicy(
    allow_private_network_targets=False,
    allowed_schemes=frozenset({"http", "https"}),
)


def test_nat64_embedded_loopback_is_blocked() -> None:
    # 64:ff9b::7f00:1 is the NAT64 well-known prefix embedding 127.0.0.1.
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[64:ff9b::7f00:1]/", _POLICY)


def test_sixtofour_embedded_loopback_is_blocked() -> None:
    # 2002:7f00:1:: is a 6to4 address embedding 127.0.0.1.
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2002:7f00:1::]/", _POLICY)


def test_nat64_embedded_public_ipv4_is_allowed() -> None:
    # 64:ff9b::808:808 embeds the public address 8.8.8.8 -> must not be over-blocked.
    enforce_web_fetch_egress("http://[64:ff9b::808:808]/", _POLICY)
