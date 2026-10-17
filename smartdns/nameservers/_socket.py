"""上游侧的 anyio → dnspython Socket 适配器（可选重复发包与抗抢答技巧）。"""

from socket import MSG_OOB

from anyio.abc import SocketAttribute
from dns.inet import low_level_address_tuple

from smartdns.utils.sockets import (
    DatagramSocketAdapter,
    StreamSocketAdapter,
    dns_timeout,
    underlying_socket,
)


class AnyioDatagramSocket(DatagramSocketAdapter):
    """已连接的上游 UDP 套接字：可重复发包，可跳过疑似抢答的伪造应答。"""

    def __init__(self, sock, repeat: int = 0, use_tricks: bool = False):
        super().__init__(sock)
        self._repeat = repeat
        self._use_tricks = use_tricks
        # anyio 将 IPv6 对端地址规约为 (host, port) 二元组，而 dnspython 校验
        # 应答来源的 _matches_destination 期望低层四元组 (host, port, flowinfo,
        # scope_id)；不转换时 IPv6 上游的应答会被 ignore_unexpected 静默丢弃，
        # 表现为已收到应答仍按超时上报。
        remote = sock.extra(SocketAttribute.remote_address, None)
        self._addr = low_level_address_tuple(remote) if remote is not None else None

    async def sendto(self, what, destination, timeout):
        with dns_timeout(timeout):
            # UDP socket 已连接，destination 仅用于兼容 dnspython 接口。
            for _ in range(self._repeat + 1):
                await self._sock.send(what)
        return len(what)

    async def recvfrom(self, size, timeout):
        with dns_timeout(timeout):
            data = await self._sock.receive()
            if self._use_tricks:
                # 对 EDNS 查询的真实应答必带 OPT（ARCOUNT ≥ 1），抢答注入的伪造
                # 包通常没有；跳过这类包直到超时（UDP socket 已连接，只收上游）。
                while len(data) <= 32 or data[10:12] == b"\x00\x00":
                    data = await self._sock.receive()
            return data[:size], self._addr

    async def getpeername(self):
        return self._addr


class AnyioStreamSocket(StreamSocketAdapter):
    """上游 TCP/TLS 连接；``use_tricks`` 时先以 OOB 方式发送报文前缀。"""

    def __init__(self, stream, use_tricks: bool = False):
        super().__init__(stream)
        self._use_tricks = use_tricks

    def _send_trick_prefix(self, what: bytes) -> bool:
        """尝试以 OOB 方式发送报文前缀，不改变 AnyIO socket 的阻塞状态。"""
        if not self._use_tricks or len(what) <= 32:
            return False

        try:
            socket = underlying_socket(self._stream)
            if socket is None:
                return False
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
        if self._send_trick_prefix(what):
            what = what[16:]
        await super().sendall(what, timeout)
