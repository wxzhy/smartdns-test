"""UDP Listener 包装原始 socket 失败时的资源清理测试。"""

from socket import AF_INET

import dns.exception
import pytest
from anyio import ClosedResourceError
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


@pytest.mark.parametrize(
    ("receive_error", "expected_sleeps"),
    [
        (dns.exception.FormError("bad packet"), []),
        (OSError("socket failed"), [0.1]),
    ],
)
async def test_receive_error_backoff_policy(
    monkeypatch, receive_error: Exception, expected_sleeps: list[float]
) -> None:
    raw_socket = _RawSocket()
    listener = _listener()
    monkeypatch.setattr(listener, "_create_socket", lambda: raw_socket)

    class _FakeUDPSocket:
        def extra(self, attribute: object, default: object = None) -> object:
            if attribute is SocketAttribute.family:
                return AF_INET
            return default

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

    calls = 0

    async def fake_receive_udp(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise receive_error
        raise ClosedResourceError

    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("smartdns.listeners.udp.UDPSocket", _UDPSocketFactory)
    monkeypatch.setattr("smartdns.listeners.udp.receive_udp", fake_receive_udp)
    monkeypatch.setattr("smartdns.listeners.udp.sleep", fake_sleep)

    async def handler(request):
        return None

    await listener.start(handler)

    assert calls == 2
    assert sleeps == expected_sleeps
