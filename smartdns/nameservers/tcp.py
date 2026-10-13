"""DNS over TCP 上游。"""

from typing import TYPE_CHECKING

from anyio import connect_tcp, fail_after
from loguru import logger

from smartdns.nameservers._pool import HealthCheckedTCPConnectionManager
from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers._stream import StreamNameserver

if TYPE_CHECKING:
    from anyio.abc import SocketStream

    from smartdns.models.nameserver import TCPNameserverConfig
    from smartdns.nameservers._pool import TrackedStream


class TCPNameserver(StreamNameserver):
    """TCP 上游解析器（DNS over TCP）；``use_tricks`` 尝试 OOB 前缀发送。"""

    def __init__(self, config: TCPNameserverConfig):
        super().__init__(config)
        self._use_tricks = config.use_tricks

    def kind(self) -> str:
        return "tcp"

    def _connection_manager(self) -> HealthCheckedTCPConnectionManager:
        return HealthCheckedTCPConnectionManager(connect_timeout=self.timeout)

    async def _connect(self, timeout: float) -> SocketStream:
        with fail_after(timeout):
            return await connect_tcp(self.host, self.port)

    def _wrap(self, stream: TrackedStream | SocketStream) -> AnyioStreamSocket:
        return AnyioStreamSocket(stream, use_tricks=self._use_tricks)

    async def start(self):
        """启动 TCP 上游；pool_size>0 时创建连接池以复用连接。"""
        await super().start()
        logger.info(
            "TCP 上游 {} 已启动，目标: {}:{}，连接池: {}",
            self.name,
            self.host,
            self.port,
            self._pool_size or "关闭",
        )
