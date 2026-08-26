"""UDP Listener 包装原始 socket 失败时的资源清理测试。"""

import pytest

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
