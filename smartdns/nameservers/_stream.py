"""流式（2 字节长度前缀分帧）上游的公共实现：DNS over TCP 与 DNS over TLS。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import dns.asyncbackend
import dns.asyncquery
import dns.message
from anyio import CancelScope
from loguru import logger

from smartdns.nameservers._pool_compat import CancellationSafeConnectionPool
from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers.base import (
    BaseAddressNameserver,
    query_deadline,
    remaining_timeout,
)

if TYPE_CHECKING:
    from generic_connection_pool.asyncio import BaseConnectionManager, ConnectionPool

    from smartdns.models.nameserver import TCPNameserverConfig, TLSNameserverConfig
    from smartdns.nameservers._pool import TcpEndpoint


class StreamNameserver(BaseAddressNameserver):
    """``pool_size > 0`` 时复用连接池中的连接，否则每次查询新建连接。

    子类提供 ``_connection_manager``（池化建连）与 ``_connect``（单次建连）。
    """

    def __init__(self, config: TCPNameserverConfig | TLSNameserverConfig) -> None:
        super().__init__(config)
        self.host = config.address
        self.port = config.port
        self._pool_size = config.pool_size
        self._pool: ConnectionPool[TcpEndpoint, Any] | None = None

    def _connection_manager(self) -> BaseConnectionManager[TcpEndpoint, Any]:
        raise NotImplementedError

    async def _connect(self, timeout: float) -> Any:
        """新建一条连接；超时须同时覆盖建连与握手。"""
        raise NotImplementedError

    def _wrap(self, stream: Any) -> AnyioStreamSocket:
        """把连接包装成 dnspython 可用的 StreamSocket。"""
        return AnyioStreamSocket(stream)

    async def start(self) -> None:
        if self._pool_size:
            self._pool = CancellationSafeConnectionPool(
                self._connection_manager(),
                min_idle=1,
                max_size=self._pool_size,
                total_max_size=self._pool_size,
            )

    async def stop(self) -> None:
        """关闭连接池（若有）。"""
        pool = self._pool
        self._pool = None
        if pool is not None:
            await pool.close()

    async def _query_on_stream(
        self,
        stream: Any,
        request: dns.message.QueryMessage,
        timeout: float,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        # 传入 sock 时 dnspython 不会关闭它，连接可在多次查询间复用。
        return await dns.asyncquery.tcp(
            request,
            where=self.address,
            timeout=timeout,
            port=self.port,
            sock=self._wrap(stream),
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
        # 获取连接、建连/握手与收发共用同一截止时刻，黑洞地址不会挂到 OS 级超时。
        deadline = query_deadline(timeout, self.timeout)
        try:
            if self._pool is not None:
                endpoint: TcpEndpoint = (self.address, self.port)
                async with self._pool.connection(
                    endpoint, timeout=remaining_timeout(deadline)
                ) as conn:
                    try:
                        return await self._query_on_stream(
                            conn,
                            request,
                            remaining_timeout(deadline),
                            one_rr_per_rrset,
                            ignore_trailing,
                        )
                    except BaseException:
                        # 交换中途失败（含取消）后帧/记录层对齐不可信；残留数据可能
                        # 已读入用户态缓冲，健康检查看不到，须由交换方显式标记。
                        conn.healthy = False
                        raise
            conn = await self._connect(remaining_timeout(deadline))
            try:
                return await self._query_on_stream(
                    conn,
                    request,
                    remaining_timeout(deadline),
                    one_rr_per_rrset,
                    ignore_trailing,
                )
            finally:
                with CancelScope(shield=True):
                    await conn.aclose()
        except Exception as error:
            logger.warning(
                "{} 上游 {} 查询失败: {}: {}",
                self.kind().upper(),
                self.name,
                type(error).__name__,
                error,
            )
            raise
