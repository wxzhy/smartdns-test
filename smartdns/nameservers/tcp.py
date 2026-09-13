from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.asyncquery
import dns.message
from anyio import connect_tcp, fail_after
from generic_connection_pool.asyncio import ConnectionPool
from loguru import logger

from smartdns.nameservers._pool import (
    HealthCheckedTCPConnectionManager,
    TcpEndpoint,
    TrackedStream,
)
from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers.base import (
    BaseAddressNameserver,
    query_deadline,
    remaining_timeout,
)

if TYPE_CHECKING:
    from anyio.abc import SocketStream

    from smartdns.models.nameserver import TCPNameserverConfig


class TCPNameserver(BaseAddressNameserver):
    """TCP 上游解析器（DNS over TCP）。"""

    def __init__(self, config: TCPNameserverConfig):
        super().__init__(config)
        self._pool_size = config.pool_size
        self._pool: ConnectionPool[TcpEndpoint, TrackedStream] | None = None
        self.host = config.address
        self.port = config.port
        self._use_tricks = config.use_tricks

    def kind(self) -> str:
        return "tcp"

    async def start(self):
        """启动 TCP 上游；pool_size>0 时创建连接池以复用连接。"""
        if self._pool_size:
            self._pool = ConnectionPool(
                HealthCheckedTCPConnectionManager(connect_timeout=self.timeout),
                min_idle=1,
                max_size=self._pool_size,
                total_max_size=self._pool_size,
            )
        logger.info("TCP 上游 {} 已启动，目标: {}:{}", self.name, self.host, self.port)

    async def stop(self):
        """停止 TCP 上游，关闭连接池。"""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _query_on_stream(
        self,
        raw_sock: TrackedStream | SocketStream,
        request: dns.message.QueryMessage,
        timeout: float,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        sock = AnyioStreamSocket(raw_sock, use_tricks=self._use_tricks)
        return await dns.asyncquery.tcp(
            request,
            where=self.address,
            timeout=timeout,
            port=self.port,
            sock=sock,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        deadline = query_deadline(timeout, self.timeout)
        endpoint: TcpEndpoint = (self.address, self.port)
        try:
            if self._pool is not None:
                async with self._pool.connection(
                    endpoint, timeout=remaining_timeout(deadline)
                ) as raw_sock:
                    try:
                        return await self._query_on_stream(
                            raw_sock,
                            request,
                            remaining_timeout(deadline),
                            one_rr_per_rrset,
                            ignore_trailing,
                        )
                    except Exception:
                        # 交换中途失败（如超时打断半读应答）后帧对齐不可信，
                        # 标记脏连接，归还池后由健康检查在下次获取时重建。
                        raw_sock.healthy = False
                        raise
            # 无池路径：建连与查询共用同一截止时刻，黑洞地址不会挂到 OS 级超时。
            with fail_after(remaining_timeout(deadline)):
                raw_sock = await connect_tcp(self.host, self.port)
            try:
                return await self._query_on_stream(
                    raw_sock,
                    request,
                    remaining_timeout(deadline),
                    one_rr_per_rrset,
                    ignore_trailing,
                )
            finally:
                await raw_sock.aclose()
        except Exception:
            logger.warning("TCP 上游 {} 查询失败", self.name)
            raise
