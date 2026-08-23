"""Egress policy for user-controlled web_fetch URLs (SSRF guard)."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

_IPV4_LOW_BITS_MASK = 0xFFFFFFFF


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address embedded in an IPv6 literal, if any.

    Covers the standard IPv4-in-IPv6 mechanisms: IPv4-mapped
    (``::ffff:a.b.c.d``), 6to4 (``2002::/16``), and Teredo (``2001::/32``,
    using the de-obfuscated client address). NAT64 (RFC 6052) is handled as a
    fallback: gateways commonly use the "Well-Known Prefix" ``64:ff9b::/96``,
    but RFC 6052/7050 also allows arbitrary site-defined ("custom") prefixes
    that cannot be enumerated in advance. Any IPv6 literal not covered by the
    mechanisms above is therefore treated as a possible NAT64-style embedding
    of the low 32 bits, so a custom-prefix NAT64 literal that maps to a
    private/loopback/link-local IPv4 is rejected the same way the well-known
    prefix is. Real NAT64 traffic to a public IPv4 is unaffected because the
    candidate address is itself global and passes ``is_global``.
    """

    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    teredo = ip.teredo
    if teredo is not None:
        _server, client = teredo
        return client
    return ipaddress.IPv4Address(int(ip) & _IPV4_LOW_BITS_MASK)


def _egress_ip_is_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool = False,
) -> bool:
    """Return True when an address is non-global or embeds a non-global IPv4.

    ``allow_loopback`` carves out an exception for loopback addresses
    (127.0.0.0/8, ``::1``) while still blocking every other private,
    link-local (including cloud metadata), or CGNAT address. It backs
    :attr:`WebFetchEgressPolicy.allow_loopback_targets`, used by the admin
    local-provider probe to reach an operator's own localhost server without
    opening up the general-purpose ``web_fetch`` private-network bypass.
    """

    if allow_loopback and ip.is_loopback:
        return False
    if not ip.is_global:
        return True
    embedded = _embedded_ipv4(ip)
    return embedded is not None and not embedded.is_global


@dataclass(frozen=True, slots=True)
class WebFetchEgressPolicy:
    """Egress rules for user-influenced web_fetch URLs."""

    allow_private_network_targets: bool
    allowed_schemes: frozenset[str]
    # Permit loopback (127.0.0.0/8, ::1, "localhost") even when
    # allow_private_network_targets is False. Every other private/link-local/
    # CGNAT address stays blocked. Used by the admin local-provider probe,
    # which must reach an operator's own localhost LM Studio/llama.cpp/Ollama
    # server but should not blindly fetch a config-supplied cloud-metadata or
    # internal LAN address.
    allow_loopback_targets: bool = False


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
    is_loopback_hostname = host_lower == "localhost" or host_lower.endswith(
        ".localhost"
    )
    if is_loopback_hostname and not policy.allow_loopback_targets:
        raise WebFetchEgressViolation("localhost targets are not allowed for web_fetch")
    if host_lower.endswith(".local"):
        raise WebFetchEgressViolation(".local hostnames are not allowed for web_fetch")

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if _egress_ip_is_blocked(
            parsed_ip, allow_loopback=policy.allow_loopback_targets
        ):
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
        if _egress_ip_is_blocked(
            resolved, allow_loopback=policy.allow_loopback_targets
        ):
            raise WebFetchEgressViolation(
                f"Host {host!r} resolves to a non-public address ({resolved})"
            )
    return infos


def enforce_web_fetch_egress(url: str, policy: WebFetchEgressPolicy) -> None:
    """Validate ``url`` (scheme, host, and resolved addresses) for web_fetch."""
    get_validated_stream_addrinfos_for_egress(url, policy)
