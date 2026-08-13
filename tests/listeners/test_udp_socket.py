"""UDP Listener socket 适配器的并发写入回归测试。"""

from socket import AF_INET

from anyio import BusyResourceError, create_task_group, sleep
from anyio.abc import SocketAttribute

from smartdns.listeners._socket import AnyioDatagramSocket


class _WriteGuardedSocket:
    """模拟 AnyIO UDPSocket：并发 sendto 时直接抛 BusyResourceError。"""

    def __init__(self) -> None:
        self.writing = False
        self.sent: list[tuple[bytes, str, int]] = []

    def extra(self, attribute: object, default: object = None) -> object:
        if attribute is SocketAttribute.family:
            return AF_INET
        return default

    async def sendto(self, data: bytes, host: str, port: int) -> None:
        if self.writing:
            raise BusyResourceError("writing to")
        self.writing = True
        try:
            await sleep(0.01)
            self.sent.append((data, host, port))
        finally:
            self.writing = False


async def test_concurrent_udp_writes_are_serialized() -> None:
    raw_socket = _WriteGuardedSocket()
    socket = AnyioDatagramSocket(raw_socket)

    async def send(index: int) -> None:
        data = index.to_bytes()
        assert await socket.sendto(data, ("127.0.0.1", 5300 + index), 1) == len(data)

    async with create_task_group() as task_group:
        for index in range(8):
            task_group.start_soon(send, index)

    assert len(raw_socket.sent) == 8
    assert {port for _, _, port in raw_socket.sent} == set(range(5300, 5308))
