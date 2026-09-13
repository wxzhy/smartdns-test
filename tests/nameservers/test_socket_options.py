"""UDP/TCP 上游兼容发送选项的回归测试。"""

from socket import AF_INET, MSG_OOB

import pytest
from anyio.abc import SocketAttribute

from smartdns.models.nameserver import TCPNameserverConfig, UDPNameserverConfig
from smartdns.nameservers._socket import AnyioDatagramSocket, AnyioStreamSocket


class _FakeDatagramSocket:
    def __init__(self, packets: list[bytes] | None = None) -> None:
        self.sent: list[bytes] = []
        self.packets = list(packets or [])

    def extra(self, attribute: object, default: object = None) -> object:
        if attribute is SocketAttribute.family:
            return AF_INET
        if attribute is SocketAttribute.remote_address:
            return ("1.1.1.1", 53)
        if attribute is SocketAttribute.local_address:
            return ("127.0.0.1", 53000)
        return default

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return self.packets.pop(0)

    async def aclose(self) -> None:
        return None


class _FakeRawSocket:
    def __init__(
        self, error: Exception | None = None, sent_size: int | None = None
    ) -> None:
        self.error = error
        self.sent_size = sent_size
        self.sent: list[tuple[bytes, int]] = []
        self.blocking_changes: list[bool] = []

    def send(self, data: bytes, flags: int) -> int:
        if self.error is not None:
            raise self.error
        self.sent.append((data, flags))
        return len(data) if self.sent_size is None else self.sent_size

    def setblocking(self, value: bool) -> None:
        self.blocking_changes.append(value)


class _RawSocketWrapper:
    def __init__(self, socket: _FakeRawSocket) -> None:
        self._sock = socket


class _FakeStream:
    def __init__(self, raw_socket: _FakeRawSocket) -> None:
        self.raw_socket = _RawSocketWrapper(raw_socket)
        self.sent: list[bytes] = []

    def extra(self, attribute: object, default: object = None) -> object:
        if attribute is SocketAttribute.family:
            return AF_INET
        if attribute is SocketAttribute.raw_socket:
            return self.raw_socket
        return default

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self, size: int = 65536) -> bytes:
        return b""

    async def aclose(self) -> None:
        return None


def test_udp_and_tcp_config_accept_compatibility_options() -> None:
    udp = UDPNameserverConfig(
        name="udp", type="udp", address="1.1.1.1", port=53, repeat=2, use_tricks=True
    )
    tcp = TCPNameserverConfig(
        name="tcp", type="tcp", address="8.8.8.8", port=53, use_tricks=True
    )

    assert udp.repeat == 2
    assert udp.use_tricks is True
    assert tcp.use_tricks is True


async def test_udp_repeat_sends_original_plus_configured_repeats() -> None:
    raw_socket = _FakeDatagramSocket()
    socket = AnyioDatagramSocket(raw_socket, repeat=2)

    assert await socket.sendto(b"query", None, 1) == 5
    assert raw_socket.sent == [b"query", b"query", b"query"]


async def test_udp_use_tricks_skips_invalid_packet() -> None:
    invalid = bytes(33)
    valid = bytearray(33)
    valid[10:12] = b"\x00\x01"
    raw_socket = _FakeDatagramSocket([invalid, bytes(valid)])
    socket = AnyioDatagramSocket(raw_socket, use_tricks=True)

    data, address = await socket.recvfrom(512, 1)

    assert data == bytes(valid)
    assert address == ("1.1.1.1", 53)


async def test_tcp_use_tricks_sends_oob_prefix_then_remainder() -> None:
    payload = bytes(range(40))
    raw_socket = _FakeRawSocket()
    stream = _FakeStream(raw_socket)
    socket = AnyioStreamSocket(stream, use_tricks=True)

    await socket.sendall(payload, 1)

    assert raw_socket.sent == [(payload[:16] + b"\x00", MSG_OOB)]
    assert raw_socket.blocking_changes == []
    assert stream.sent == [payload[16:]]


async def test_tcp_trick_failure_falls_back_to_complete_payload() -> None:
    payload = bytes(range(40))
    raw_socket = _FakeRawSocket(OSError("OOB is unsupported"))
    stream = _FakeStream(raw_socket)
    socket = AnyioStreamSocket(stream, use_tricks=True)

    await socket.sendall(payload, 1)

    assert raw_socket.blocking_changes == []
    assert stream.sent == [payload]


async def test_tcp_trick_partial_write_does_not_duplicate_prefix() -> None:
    payload = bytes(range(40))
    raw_socket = _FakeRawSocket(sent_size=8)
    stream = _FakeStream(raw_socket)
    socket = AnyioStreamSocket(stream, use_tricks=True)

    with pytest.raises(OSError, match="仅发送"):
        await socket.sendall(payload, 1)

    assert stream.sent == []
