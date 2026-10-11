"""UDP Listener 包装原始 socket 失败时的资源清理测试。"""

from socket import AF_INET

import dns.exception
import dns.message
import dns.tsigkeyring
import pytest
from anyio import ClosedResourceError, Semaphore, sleep
from anyio.abc import SocketAttribute

from smartdns.listeners.udp import UDPListener
from smartdns.models.listener import Do53ListenerConfig


class _RawSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _listener() -> UDPListener:
    return UDPListener(
        Do53ListenerConfig(name="udp", type="udp", host="127.0.0.1", port=5353)
    )


async def test_from_socket_failure_closes_raw_socket(monkeypatch) -> None:
    raw_socket = _RawSocket()
    listener = _listener()
    monkeypatch.setattr(listener, "_create_socket", lambda: raw_socket)

    class _FailingUDPSocket:
        @classmethod
        async def from_socket(cls, sock) -> object:
            assert sock is raw_socket
            raise RuntimeError("wrap failed")

    monkeypatch.setattr("smartdns.listeners.udp.UDPSocket", _FailingUDPSocket)

    async def handler(request):
        return None

    with pytest.raises(RuntimeError, match="wrap failed"):
        await listener.start(handler)

    assert raw_socket.closed
    assert listener._sock is None
    assert listener._listener is None


def _tsig_signed_query() -> bytes:
    query = dns.message.make_query("example.com.", "A")
    query.use_tsig(
        dns.tsigkeyring.from_text({"key.": "c2VjcmV0c2VjcmV0c2VjcmV0"}),
        keyname="key.",
    )
    return query.to_wire()


@pytest.mark.parametrize(
    ("receive_result", "expected_sleeps"),
    [
        (b"\x00\x01", []),
        # UnknownTSIGKey 不是 FormError 子类，同样只能丢弃单个报文。
        (_tsig_signed_query(), []),
        (OSError("socket failed"), [0.1]),
    ],
    ids=["malformed", "tsig", "socket-error"],
)
async def test_receive_error_backoff_policy(
    monkeypatch, receive_result: bytes | Exception, expected_sleeps: list[float]
) -> None:
    raw_socket = _RawSocket()
    listener = _listener()
    monkeypatch.setattr(listener, "_create_socket", lambda: raw_socket)
    calls = 0

    class _FakeUDPSocket:
        def extra(self, attribute: object, default: object = None) -> object:
            if attribute is SocketAttribute.family:
                return AF_INET
            return default

        async def receive(self) -> tuple[bytes, tuple[str, int]]:
            nonlocal calls
            calls += 1
            if calls == 1:
                if isinstance(receive_result, Exception):
                    raise receive_result
                return receive_result, ("127.0.0.1", 12345)
            raise ClosedResourceError

        async def aclose(self) -> None:
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info) -> None:
            return None

    udp_socket = _FakeUDPSocket()

    class _UDPSocketFactory:
        @classmethod
        async def from_socket(cls, sock):
            assert sock is raw_socket
            return udp_socket

    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("smartdns.listeners.udp.UDPSocket", _UDPSocketFactory)
    monkeypatch.setattr("smartdns.listeners.udp.sleep", fake_sleep)

    async def handler(request):
        raise AssertionError("无法解析的报文不应进入处理器")

    await listener.start(handler)

    assert calls == 2
    assert sleeps == expected_sleeps


async def test_udp_queue_and_processing_share_one_deadline(monkeypatch) -> None:
    listener = _listener()
    listener.timeout = 0.18
    raw = _RawSocket()
    monkeypatch.setattr(listener, "_create_socket", lambda: raw)
    monkeypatch.setattr(
        "smartdns.listeners.udp.Semaphore", lambda capacity: Semaphore(1)
    )

    class Datagram:
        def extra(self, attribute, default=None):
            return AF_INET if attribute is SocketAttribute.family else default

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return None

        async def aclose(self):
            return None

        async def receive(self):
            message = next(queries, None)
            if message is None:
                raise ClosedResourceError
            return message.to_wire(), ("127.0.0.1", 12345)

    datagram = Datagram()

    class Factory:
        @classmethod
        async def from_socket(cls, sock):
            return datagram

    first, second = (
        dns.message.make_query(name, "A")
        for name in ("first.example.com.", "second.example.com.")
    )
    first.id, second.id = 1, 2
    queries = iter([first, second])
    sent: list[int] = []

    async def send(sock, wire, client, **kwargs):
        sent.append(dns.message.from_wire(wire).id)

    async def handler(request):
        await sleep(0.11 if request.id == first.id else 0.10)
        return dns.message.make_response(request.msg)

    monkeypatch.setattr("smartdns.listeners.udp.UDPSocket", Factory)
    monkeypatch.setattr("smartdns.listeners.udp.send_udp", send)
    try:
        await listener.start(handler)
        assert sent == [first.id]
    finally:
        await listener.stop()
