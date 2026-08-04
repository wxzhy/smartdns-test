from socket import SOCK_DGRAM, SOCK_STREAM

from anyio import EndOfStream, fail_after
from anyio.abc import SocketAttribute
from dns._asyncbackend import DatagramSocket, StreamSocket
from dns.exception import Timeout


class AnyioDatagramSocket(DatagramSocket):
    """基于 anyio 的 DatagramSocket 实现，支持超时处理。"""

    def __init__(self, sock):
        self._sock = sock
        super().__init__(
            family=sock.extra(SocketAttribute.family, None), type=SOCK_DGRAM
        )

    async def sendto(self, what, destination, timeout):
        try:
            with fail_after(timeout):
                await self._sock.sendto(what, destination[0], destination[1])
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err
        return len(what)

    async def recvfrom(self, size, timeout):
        try:
            with fail_after(timeout):
                data, addr = await self._sock.receive()
                return data[:size], addr
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err

    async def close(self):
        await self._sock.aclose()

    async def getpeername(self):
        return self._sock.extra(SocketAttribute.remote_address, None)

    async def getsockname(self):
        return self._sock.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout):
        return None


class AnyioStreamSocket(StreamSocket):
    """基于 anyio 的 StreamSocket 实现，支持超时处理。"""

    def __init__(self, stream):
        self._stream = stream
        super().__init__(
            family=stream.extra(SocketAttribute.family, None), type=SOCK_STREAM
        )

    async def sendall(self, what, timeout):
        try:
            with fail_after(timeout):
                return await self._stream.send(what)
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err

    async def recv(self, size, timeout):
        try:
            with fail_after(timeout):
                return await self._stream.receive(size)
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err
        except EndOfStream:
            # 对端关闭连接，返回空字节以模拟 dnspython 期望的 EOF 行为。
            return b""

    async def close(self):
        await self._stream.aclose()

    async def getpeername(self):
        return self._stream.extra(SocketAttribute.remote_address, None)

    async def getsockname(self):
        return self._stream.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout):
        return None
