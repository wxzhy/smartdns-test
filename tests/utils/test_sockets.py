"""anyio → dnspython Socket 公共适配层。"""

import pytest
from anyio import EndOfStream, sleep
from anyio.abc import SocketAttribute
from dns.exception import Timeout

from smartdns.utils.sockets import StreamSocketAdapter, dns_timeout, underlying_socket


class _Stream:
    def __init__(self, raw: object = None, chunks: list[bytes] | None = None) -> None:
        self.raw = raw
        self.chunks = list(chunks or [])

    def extra(self, attribute: object, default: object = None) -> object:
        if attribute is SocketAttribute.raw_socket:
            return self.raw
        return default

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if not self.chunks:
            raise EndOfStream
        return self.chunks.pop(0)[:max_bytes]


class _TransportSocket:
    def __init__(self, sock: object) -> None:
        self._sock = sock


async def test_dns_timeout_raises_dnspython_timeout() -> None:
    with pytest.raises(Timeout), dns_timeout(0.01):
        await sleep(1)


def test_underlying_socket_unwraps_transport_socket() -> None:
    real = object()
    assert underlying_socket(_Stream(_TransportSocket(real))) is real
    assert underlying_socket(_Stream(real)) is real
    assert underlying_socket(_Stream(None)) is None


async def test_stream_adapter_maps_end_of_stream_to_empty_bytes() -> None:
    adapter = StreamSocketAdapter(_Stream(chunks=[b"abc"]))
    assert await adapter.recv(2, 1.0) == b"ab"
    assert await adapter.recv(2, 1.0) == b""
