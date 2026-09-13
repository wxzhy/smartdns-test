from socket import MSG_OOB, SOCK_DGRAM, SOCK_STREAM

from anyio import EndOfStream, fail_after
from anyio.abc import SocketAttribute
from dns._asyncbackend import DatagramSocket, StreamSocket
from dns.exception import Timeout
from dns.inet import low_level_address_tuple

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
        # anyio 将 IPv6 对端地址规约为 (host, port) 二元组，而 dnspython 校验
        # 应答来源的 _matches_destination 期望低层四元组 (host, port, flowinfo,
        # scope_id)；不转换时 IPv6 上游的应答会被 ignore_unexpected 静默丢弃，
        # 表现为已收到应答仍按超时上报。
        remote = sock.extra(SocketAttribute.remote_address, None)
        self._addr = low_level_address_tuple(remote) if remote is not None else None

    async def sendto(self, what, destination, timeout):
        try:
            with fail_after(timeout):
                # UDP socket 已连接，destination 仅用于兼容 dnspython 接口。
                for _ in range(self._repeat + 1):
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
        return self._addr

    async def getsockname(self):
        return self._sock.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout):
        return None


class AnyioStreamSocket(StreamSocket):
    """基于anyio的StreamSocket实现，支持超时处理"""

    def __init__(self, stream, use_tricks: bool = False):
        super().__init__(
            family=stream.extra(SocketAttribute.family, None), type=SOCK_STREAM
        )
        self._stream = stream
        self._use_tricks = use_tricks

    def _send_trick_prefix(self, what: bytes) -> bool:
        """尝试以 OOB 方式发送报文前缀，不改变 AnyIO socket 的阻塞状态。"""
        if not self._use_tricks or len(what) <= 32:
            return False

        try:
            raw_socket = self._stream.extra(SocketAttribute.raw_socket, None)
            if raw_socket is None:
                return False

            # asyncio 后端暴露的是 TransportSocket，实际 socket 位于 _sock；
            # 其他后端可能直接返回标准库 socket。
            socket = getattr(raw_socket, "_sock", raw_socket)
            trick_prefix = what[:16] + b"\x00"
            sent = socket.send(trick_prefix, MSG_OOB)
        except Exception:
            # 该技巧不是查询成功的必要条件。平台或后端不支持时由调用方
            # 回退为完整报文的普通异步发送。
            return False
        if sent != len(trick_prefix):
            # 部分前缀已经进入 TCP 流，此时回退发送完整报文会重复前缀并
            # 破坏 DNS 长度帧；让本次交换失败并由连接池丢弃该连接。
            raise OSError(f"OOB 前缀仅发送 {sent}/{len(trick_prefix)} 字节")
        return True

    async def sendall(self, what, timeout):
        try:
            with fail_after(timeout):
                if self._send_trick_prefix(what):
                    what = what[16:]
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
