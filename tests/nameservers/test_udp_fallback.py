"""UDP 上游截断检测和 TCP fallback 回归测试。"""

from typing import cast

import dns.asyncbackend
import dns.message

from smartdns.models.nameserver import UDPNameserverConfig
from smartdns.nameservers.udp import UDPNameserver


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        return None


def _nameserver() -> UDPNameserver:
    return UDPNameserver(
        UDPNameserverConfig(name="upstream", type="udp", address="1.1.1.1", port=53)
    )


async def test_udp_query_requests_truncation_exception(monkeypatch) -> None:
    raw_socket = object()
    captured: dict[str, object] = {}

    async def create_socket(*args: object, **kwargs: object) -> _AsyncContext:
        return _AsyncContext(raw_socket)

    async def query(*args: object, **kwargs: object) -> dns.message.Message:
        captured.update(kwargs)
        return dns.message.make_response(cast("dns.message.Message", args[0]))

    monkeypatch.setattr(
        "smartdns.nameservers.udp.create_connected_udp_socket", create_socket
    )
    monkeypatch.setattr(
        "smartdns.nameservers.udp.AnyioDatagramSocket", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr("smartdns.nameservers.udp.dns.asyncquery.udp", query)

    request = dns.message.make_query("example.com.", "A")
    await _nameserver().async_query(
        request,
        timeout=1,
        source=None,
        source_port=0,
        max_size=False,
        backend=cast("dns.asyncbackend.Backend", object()),
    )

    assert captured["raise_on_truncation"] is True


async def test_max_size_retries_same_udp_upstream_over_tcp(monkeypatch) -> None:
    raw_stream = object()
    captured: dict[str, object] = {}

    async def connect(*args: object, **kwargs: object) -> _AsyncContext:
        return _AsyncContext(raw_stream)

    async def query(*args: object, **kwargs: object) -> dns.message.Message:
        captured.update(kwargs)
        return dns.message.make_response(cast("dns.message.Message", args[0]))

    monkeypatch.setattr("smartdns.nameservers.udp.connect_tcp", connect)
    monkeypatch.setattr(
        "smartdns.nameservers.udp.AnyioStreamSocket", lambda stream: stream
    )
    monkeypatch.setattr("smartdns.nameservers.udp.dns.asyncquery.tcp", query)

    request = dns.message.make_query("example.com.", "TXT")
    await _nameserver().async_query(
        request,
        timeout=1,
        source=None,
        source_port=0,
        max_size=True,
        backend=cast("dns.asyncbackend.Backend", object()),
    )

    assert captured["sock"] is raw_stream
