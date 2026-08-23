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


def test_custom_prefix_nat64_embedded_loopback_is_blocked() -> None:
    # 2620:0:aaaa::7f00:1 is NOT the RFC 6052 well-known prefix, but its low 32
    # bits still decode to 127.0.0.1 under a NAT64-style (site-defined/custom
    # prefix) embedding. Custom NAT64 prefixes cannot be enumerated in
    # advance, so the guard must treat any such globally-routable IPv6
    # literal conservatively.
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2620:0:aaaa::7f00:1]/", _POLICY)


def test_custom_prefix_nat64_embedded_private_ipv4_is_blocked() -> None:
    # Low 32 bits decode to 10.1.2.3 (RFC 1918 private).
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2620:0:aaaa::a01:203]/", _POLICY)


def test_custom_prefix_nat64_embedded_link_local_is_blocked() -> None:
    # Low 32 bits decode to 169.254.169.254 (cloud metadata / link-local).
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2620:0:aaaa::a9fe:a9fe]/", _POLICY)


def test_custom_prefix_nat64_embedded_public_ipv4_is_allowed() -> None:
    # Low 32 bits decode to 8.8.8.8 (public) -> a real custom-prefix NAT64
    # target reaching a public IPv4 must not be over-blocked.
    enforce_web_fetch_egress("http://[2620:0:aaaa::808:808]/", _POLICY)


def test_teredo_embedded_loopback_client_is_blocked() -> None:
    # 2001:0:c000:201::80ff:fffe is a Teredo (RFC 4380) address whose
    # de-obfuscated client address is 127.0.0.1.
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2001:0:c000:201::80ff:fffe]/", _POLICY)


def test_teredo_embedded_private_client_is_blocked() -> None:
    # De-obfuscated Teredo client address is 10.1.2.3 (RFC 1918 private).
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2001:0:c000:201::f5fe:fdfc]/", _POLICY)


def test_teredo_embedded_link_local_client_is_blocked() -> None:
    # De-obfuscated Teredo client address is 169.254.169.254 (link-local /
    # cloud metadata).
    with pytest.raises(WebFetchEgressViolation):
        enforce_web_fetch_egress("http://[2001:0:c000:201::5601:5601]/", _POLICY)
