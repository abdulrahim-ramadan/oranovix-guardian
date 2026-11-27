"""
One line of an access log, and who really sent it.

``X-Forwarded-For`` is written by whoever sends the request, so it is
only believed when the direct peer is one of the user's own proxies.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple, Union

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(frozen=True)
class AccessLogEntry:
    """A parsed request. Text fields are as the server wrote them, not decoded."""

    time: Optional[datetime]
    client_ip: str
    method: str
    path: str
    query: str
    status: int                 # 0 when the log has "-"
    size: int                   # response body bytes; 0 when the log has "-"
    referer: str = ""
    user_agent: str = ""
    raw_length: int = 0         # length of the line before it was capped
    protocol: str = ""
    peer_ip: str = ""           # the direct peer, when it differs from client_ip

    @property
    def target(self) -> str:
        """Path and query as one request target."""
        return f"{self.path}?{self.query}" if self.query else self.path

    @property
    def request_line(self) -> str:
        return " ".join(part for part in (self.method, self.target, self.protocol) if part)


class NetworkList:
    """IP addresses and CIDR ranges, e.g. trusted proxies or an allowlist."""

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._networks: List[IpNetwork] = []
        self.invalid: List[str] = []
        for entry in entries:
            text = str(entry).strip()
            if not text:
                continue
            try:
                self._networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                self.invalid.append(text)

    def __bool__(self) -> bool:
        return bool(self._networks)

    @property
    def entries(self) -> Tuple[str, ...]:
        return tuple(str(network) for network in self._networks)

    def contains(self, address: str) -> bool:
        if not self._networks:
            return False
        ip = parse_ip(address)
        if ip is None:
            return False
        return any(ip.version == network.version and ip in network for network in self._networks)


def parse_ip(text: str) -> Optional[IpAddress]:
    """An address as logged: brackets and an IPv4 port are tolerated."""
    value = text.strip().strip("[]")
    if value.count(":") == 1 and "." in value:      # "203.0.113.5:4711"
        value = value.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


class ClientAddressResolver:
    """Picks the client address from the peer and the ``X-Forwarded-For`` header."""

    def __init__(self, trusted_proxies: Iterable[str] = ()) -> None:
        self._trusted = NetworkList(trusted_proxies)

    @property
    def trusted(self) -> NetworkList:
        return self._trusted

    def resolve(self, peer: str, forwarded_for: str = "") -> str:
        """The header is walked from the right: each hop that is a trusted proxy is skipped.

        Without trusted proxies the header is ignored, because anyone can write it.
        """
        if not self._trusted or not forwarded_for:
            return peer.strip()
        peer_ip = parse_ip(peer)
        peer_text = str(peer_ip) if peer_ip is not None else peer.strip()
        if not self._trusted.contains(peer_text):
            return peer_text
        hops = [hop.strip() for hop in forwarded_for.split(",") if hop.strip() and hop.strip() != "-"]
        for hop in reversed(hops):
            hop_ip = parse_ip(hop)
            if hop_ip is None:
                break                       # garbage in the header: stop trusting it
            if not self._trusted.contains(str(hop_ip)):
                return str(hop_ip)
        return peer_text
