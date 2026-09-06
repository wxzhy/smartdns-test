import socket

from anyio import connect_tcp, fail_after
from anyio.abc import SocketAttribute, SocketStream
from generic_connection_pool.asyncio import BaseConnectionManager

TcpEndpoint = tuple[str, int]


class TCPStreamConnectionManager(BaseConnectionManager[TcpEndpoint, SocketStream]):
    """基于 anyio SocketStream 的 TCP 连接管理器，供 generic_connection_pool 复用连接。

    连接为普通 DNS-over-TCP（明文，无 TLS）。dnspython 的 dns.asyncquery.tcp 在传入
    sock 时用 NullContext 包装、不会关闭它，故连接可在多次查询间复用。
    """

    def __init__(self, connect_timeout: float = 5.0) -> None:
        self._connect_timeout = connect_timeout

    async def create(self, endpoint: TcpEndpoint) -> SocketStream:
        host, port = endpoint
        with fail_after(self._connect_timeout):
            return await connect_tcp(host, port)

    async def dispose(self, endpoint: TcpEndpoint, conn: SocketStream) -> None:
        await conn.aclose()

    async def check_aliveness(self, endpoint: TcpEndpoint, conn: SocketStream) -> bool:
        raw = conn.extra(SocketAttribute.raw_socket, None)
        if raw is None:
            return False
        # asyncio 后端返回 TransportSocket，其他后端可能直接返回标准 socket。
        probe = getattr(raw, "_sock", raw)
        try:
            probe.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            return True  # 内核缓冲无待读数据：连接存活
        except OSError:
            return False  # 对端关闭或 socket 异常：重建
        return False  # 内核缓冲有残留数据：重建


class TrackedStream:
    """池内 TCP 流的健康状态包装。

    交换过程中发生异常（如超时打断半读应答）时由使用方置 ``healthy = False``；
    健康检查据此在下次获取时重建连接，避免复用帧对齐已丢失的脏连接。
    MSG_PEEK 只能看到内核缓冲，asyncio 已读入传输缓冲的数据不可见，
    因此脏判定必须由交换方显式标记。
    """

    __slots__ = ("_stream", "healthy")

    def __init__(self, stream: SocketStream) -> None:
        self._stream = stream
        self.healthy = True

    async def send(self, data: bytes) -> None:
        await self._stream.send(data)

    async def receive(self, max_bytes: int) -> bytes:
        return await self._stream.receive(max_bytes)

    async def aclose(self) -> None:
        await self._stream.aclose()

    def extra(self, attribute: object, default: object = None) -> object:
        return self._stream.extra(attribute, default)


class HealthCheckedTCPConnectionManager(
    BaseConnectionManager[TcpEndpoint, TrackedStream]
):
    """在 TCP 连接管理之上叠加交换异常标记：异常连接获取时重建。"""

    def __init__(self, connect_timeout: float = 5.0) -> None:
        self._manager = TCPStreamConnectionManager(connect_timeout=connect_timeout)

    async def create(self, endpoint: TcpEndpoint) -> TrackedStream:
        return TrackedStream(await self._manager.create(endpoint))

    async def dispose(self, endpoint: TcpEndpoint, conn: TrackedStream) -> None:
        await self._manager.dispose(endpoint, conn._stream)

    async def check_aliveness(self, endpoint: TcpEndpoint, conn: TrackedStream) -> bool:
        if not conn.healthy:
            return False
        return await self._manager.check_aliveness(endpoint, conn._stream)
