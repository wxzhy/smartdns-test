from time import monotonic
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
from smartdns.nameservers.base import BaseAddressNameserver

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
        # 传入 timeout 为剩余 lifetime；0/None（未设置或已到期）回退到完整配置超时。
        effective_timeout = (
            timeout if timeout is not None and timeout > 0 else self.timeout
        )
        endpoint: TcpEndpoint = (self.address, self.port)
        try:
            if self._pool is not None:
                # 连接获取（含新建）计入总时限；0.1 与配置最小超时一致，
                # 避免 0 被 dns.asyncquery 当作立即超时。
                deadline = monotonic() + effective_timeout
                async with self._pool.connection(
                    endpoint, timeout=effective_timeout
                ) as raw_sock:
                    remaining = max(deadline - monotonic(), 0.1)
                    try:
                        return await self._query_on_stream(
                            raw_sock,
                            request,
                            remaining,
                            one_rr_per_rrset,
                            ignore_trailing,
                        )
                    except Exception:
                        # 交换中途失败（如超时打断半读应答）后帧对齐不可信，
                        # 标记脏连接，归还池后由健康检查在下次获取时重建。
                        raw_sock.healthy = False
                        raise
            # 无池路径：建连与查询均计入 effective_timeout，黑洞地址不会挂到 OS 级超时。
            deadline = monotonic() + effective_timeout
            with fail_after(effective_timeout):
                raw_sock = await connect_tcp(self.host, self.port)
            try:
                return await self._query_on_stream(
                    raw_sock,
                    request,
                    max(deadline - monotonic(), 0.1),
                    one_rr_per_rrset,
                    ignore_trailing,
                )
            finally:
                await raw_sock.aclose()
        except Exception:
            logger.warning("TCP 上游 {} 查询失败", self.name)
            raise
