from socket import SOCK_DGRAM, SOCK_STREAM

from anyio import EndOfStream, fail_after
from anyio.abc import SocketAttribute
from dns._asyncbackend import DatagramSocket, StreamSocket
from dns.exception import Timeout

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
        self._addr = sock.extra(SocketAttribute.remote_address, None)

    async def sendto(self, what, destination, timeout):
        try:
            with fail_after(timeout):
                if destination is None:
                    # 重复发送数据包以增加成功率
                    for _ in range(self._repeat + 1):
                        await self._sock.send(what)
                else:
                    for _ in range(self._repeat + 1):
                        # UDP socket已经连接，不需要sendto
                        # await self._sock.sendto(what, destination[0], destination[1])
                        await self._sock.send(what)
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err
        return len(what)

    async def recvfrom(self, size, timeout):
        try:
            with fail_after(timeout):
                if self._use_tricks:
                    # UDP socket 已连接，receive 即可；多次接收跳过明显伪造的包。
                    for _ in range(5):
                        data = await self._sock.receive()
                        if len(data) > 32 and data[10:12] == b"\x00\x01":
                            return data[:size], self._addr
                    # 多次接收后仍无有效数据包，按超时处理。
                    raise TimeoutError("未收到有效数据包")
                data = await self._sock.receive()
                return data[:size], self._addr
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err

    async def close(self):
        await self._sock.aclose()

    async def getpeername(self):
        return self._sock.extra(SocketAttribute.remote_address, None)

    async def getsockname(self):
        return self._sock.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout):
        raise NotImplementedError


class AnyioStreamSocket(StreamSocket):
    """基于anyio的StreamSocket实现，支持超时处理"""

    def __init__(self, stream, use_tricks: bool = False):
        super().__init__(
            family=stream.extra(SocketAttribute.family, None), type=SOCK_STREAM
        )
        self._stream = stream
        self._use_tricks = use_tricks

    async def sendall(self, what, timeout):
        try:
            with fail_after(timeout):
                # AnyIO stream 不能安全切换底层共享 socket 的阻塞模式；保留该配置
                # 作为兼容字段，统一使用普通异步发送。
                await self._stream.send(what)
        except TimeoutError as err:
            raise Timeout(timeout=timeout) from err

    async def recv(self, size, timeout):
        try:
            with fail_after(timeout):
                return await self._stream.receive(size)
        except TimeoutError as err:
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

    async def getpeercert(self, timeout):
        return None
