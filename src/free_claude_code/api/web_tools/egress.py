"""Egress policy for user-controlled web_fetch URLs (SSRF guard)."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

# Well-known NAT64 prefix (RFC 6052): embeds an IPv4 address in its low 32 bits. A
# NAT64 gateway translates ``64:ff9b::7f00:1`` back to ``127.0.0.1``, so such a
# literal must be judged by the embedded IPv4, not by ``is_global`` (which is True).
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address embedded in an IPv6 literal, if any."""

    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _egress_ip_is_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True when an address is non-global or embeds a non-global IPv4."""

    if not ip.is_global:
        return True
    embedded = _embedded_ipv4(ip)
    return embedded is not None and not embedded.is_global


@dataclass(frozen=True, slots=True)
class WebFetchEgressPolicy:
    """Egress rules for user-influenced web_fetch URLs."""

    allow_private_network_targets: bool
    allowed_schemes: frozenset[str]


class WebFetchEgressViolation(ValueError):
    """Raised when a web_fetch URL is rejected by egress policy (SSRF guard)."""


def web_fetch_allowed_scheme_set(raw_schemes: str) -> frozenset[str]:
    """Return normalized schemes allowed for web_fetch."""

    return frozenset(
        part.strip().lower() for part in raw_schemes.split(",") if part.strip()
    )


def _port_for_url(parsed) -> int:
    if parsed.port is not None:
        return parsed.port
    return 443 if (parsed.scheme or "").lower() == "https" else 80


def _stream_getaddrinfo_or_raise(host: str, port: int) -> list[tuple]:
    try:
        return socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise WebFetchEgressViolation(
            f"Could not resolve host {host!r}: {exc}"
        ) from exc


def get_validated_stream_addrinfos_for_egress(
    url: str, policy: WebFetchEgressPolicy
) -> list[tuple]:
    """Resolve and validate a URL for web_fetch, returning getaddrinfo rows for pinning.

    Each HTTP connect pins to only these `getaddrinfo` results so a malicious DNS
    server cannot rebind to a disallowed address between resolution and the TCP
    connect (used by :func:`api.web_tools.outbound._run_web_fetch`).
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in policy.allowed_schemes:
        raise WebFetchEgressViolation(
            f"URL scheme {scheme!r} is not allowed for web_fetch"
        )

    host = parsed.hostname
    if host is None or host == "":
        raise WebFetchEgressViolation("web_fetch URL must include a host")

    port = _port_for_url(parsed)

    if policy.allow_private_network_targets:
        return _stream_getaddrinfo_or_raise(host, port)

    host_lower = host.lower()
    if host_lower == "localhost" or host_lower.endswith(".localhost"):
        raise WebFetchEgressViolation("localhost targets are not allowed for web_fetch")
    if host_lower.endswith(".local"):
        raise WebFetchEgressViolation(".local hostnames are not allowed for web_fetch")

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if _egress_ip_is_blocked(parsed_ip):
            raise WebFetchEgressViolation(
                f"Non-public IP host {host!r} is not allowed for web_fetch"
            )
        return _stream_getaddrinfo_or_raise(host, port)

    infos = _stream_getaddrinfo_or_raise(host, port)
    for *_, sockaddr in infos:
        addr = sockaddr[0]
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _egress_ip_is_blocked(resolved):
            raise WebFetchEgressViolation(
                f"Host {host!r} resolves to a non-public address ({resolved})"
            )
    return infos


def enforce_web_fetch_egress(url: str, policy: WebFetchEgressPolicy) -> None:
    """Validate ``url`` (scheme, host, and resolved addresses) for web_fetch."""
    get_validated_stream_addrinfos_for_egress(url, policy)
