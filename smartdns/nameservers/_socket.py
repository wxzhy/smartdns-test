from socket import MSG_OOB, SOCK_DGRAM, SOCK_STREAM

from anyio import EndOfStream, fail_after
from anyio.abc import SocketAttribute
from dns._asyncbackend import DatagramSocket, StreamSocket
from dns.exception import Timeout
from loguru import logger

# 以下方法中名为 `timeout` 的参数是 dnspython 后端 Socket ABC 接口签名的一部分，
# 无法重命名，因此对 ASYNC109 规则在各方法上单独禁用。


class AnyioDatagramSocket(DatagramSocket):
    """基于anyio的DatagramSocket实现，支持超时处理"""

    def __init__(self, sock, repeat: int = 0, use_tricks: bool = False):
        self._sock = sock
        super().__init__(
            family=sock.extra(SocketAttribute.family, None), type=SOCK_DGRAM
        )
        self._repeat = repeat
        self._use_tricks = use_tricks
        logger.debug(
            f"创建AnyioDatagramSocket对象，sock: {sock}, repeat: {repeat}, use_tricks: {use_tricks}"
        )

    async def sendto(self, what, destination, timeout):  # noqa: ASYNC109
        try:
            with fail_after(timeout):
                if destination is None:
                    # 重复发送数据包以增加成功率
                    for _ in range(self._repeat + 1):
                        await self._sock.send(what)
                else:
                    for _ in range(self._repeat + 1):
                        await self._sock.sendto(what, destination[0], destination[1])
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err
        return len(what)

    async def recvfrom(self, size, timeout):  # noqa: ASYNC109
        try:
            with fail_after(timeout):
                # 多次接收，忽略伪造包
                if self._use_tricks:
                    for _ in range(self._repeat + 1):
                        data, addr = await self._sock.receive()
                        if len(data) > 32 and data[10:12] == b"\x00\x01":
                            return data[:size], addr
                    # 如果没有收到有效数据，则返回最后一次接收到的数据
                    raise TimeoutError("未收到有效数据包")
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

    async def getpeercert(self, timeout):  # noqa: ASYNC109
        raise NotImplementedError


class AnyioStreamSocket(StreamSocket):
    """基于anyio的StreamSocket实现，支持超时处理"""

    def __init__(self, stream, use_tricks: bool = False):
        logger.debug(f"创建AnyioStreamSocket对象，stream: {stream}")
        super().__init__(
            family=stream.extra(SocketAttribute.family, None), type=SOCK_STREAM
        )
        self._stream = stream
        self._use_tricks = use_tricks

    async def sendall(self, what, timeout):  # noqa: ASYNC109
        try:
            with fail_after(timeout):
                split = 0
                if self._use_tricks:
                    # 获取原始socket
                    raw_socket = self._stream.extra(SocketAttribute.raw_socket, None)
                    # 分段发送
                    if raw_socket is not None and len(what) > 32:
                        split = raw_socket.send(what[:16] + b"\x00", MSG_OOB)
                        what = what[16:]
                return await self._stream.send(what) + split
        except TimeoutError as err:
            logger.error(f"发送数据超时，timeout: {timeout}")
            raise Timeout(timeout=timeout) from err

    async def recv(self, size, timeout):  # noqa: ASYNC109
        try:
            with fail_after(timeout):
                return await self._stream.receive(size)
        except TimeoutError as err:
            logger.error(f"接收数据超时，timeout: {timeout}")
            raise Timeout(timeout=timeout) from err
        except EndOfStream:
            # 对端关闭连接，返回空字节以模拟 dnspython 期望的 EOF 行为
            return b""

    async def close(self):
        await self._stream.aclose()

    async def getpeername(self):
        return self._stream.extra(SocketAttribute.remote_address, None)

    async def getsockname(self):
        return self._stream.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout):  # noqa: ASYNC109
        return None
