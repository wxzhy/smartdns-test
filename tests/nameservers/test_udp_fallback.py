"""UDP 上游截断检测和 TCP fallback 回归测试。"""

from asyncio import sleep
from typing import cast

import dns.asyncbackend
import dns.message
import pytest

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
    captured: dict[str, object] = {}

    class _Stream:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def __aenter__(self) -> _Stream:
            return self

        async def __aexit__(self, *args: object) -> None:
            await self.aclose()

        async def aclose(self) -> None:
            self.calls.append("close")

    stream = _Stream()

    async def connect(*args: object, **kwargs: object) -> _Stream:
        return stream

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

    # TC 回退 TCP：连接经 AnyioStreamSocket 透传给 dns.asyncquery.tcp，事后关闭。
    assert captured["sock"] is stream
    assert stream.calls == ["close"]


async def test_max_size_tcp_retry_connect_times_out(monkeypatch) -> None:
    """TC 回退 TCP 的建连计入超时：黑洞地址不再悬挂。"""

    async def hanging_connect(*args: object, **kwargs: object) -> object:
        await sleep(30)
        raise AssertionError("建连应已被超时取消")

    monkeypatch.setattr("smartdns.nameservers.udp.connect_tcp", hanging_connect)

    request = dns.message.make_query("example.com.", "TXT")
    with pytest.raises(TimeoutError):
        await UDPNameserver(
            UDPNameserverConfig(
                name="upstream",
                type="udp",
                address="192.0.2.1",
                port=53,
                timeout=0.2,
            )
        ).async_query(
            request,
            timeout=0,
            source=None,
            source_port=0,
            max_size=True,
            backend=cast("dns.asyncbackend.Backend", object()),
        )
