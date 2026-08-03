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
        raw: socket.socket | None = conn.extra(SocketAttribute.raw_socket, None)
        if raw is None:
            return False
        try:
            # asyncio 后端的 raw_socket 是受限的 TransportSocket（禁用 recv），
            # 故复制一个真实 socket 副本做非阻塞窥探，用后即关（不影响原连接）。
            probe = raw.dup()
        except OSError:
            return False
        try:
            probe.setblocking(False)
            # 对端关闭时返回 b""；无数据时抛 BlockingIOError（仍存活）。
            return probe.recv(1, socket.MSG_PEEK) != b""
        except BlockingIOError:
            return True
        except OSError:
            return False
        finally:
            probe.close()
