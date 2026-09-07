from ipaddress import ip_address
from time import monotonic
from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.asyncquery
import dns.message
import utls
from generic_connection_pool.asyncio import ConnectionPool
from loguru import logger

from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers._tls import (
    TLSStreamConnection,
    TLSStreamConnectionManager,
    connect_tls,
)
from smartdns.nameservers.base import BaseAddressNameserver

if TYPE_CHECKING:
    from utls import SSLContext

    from smartdns.models.nameserver import TLSNameserverConfig
    from smartdns.nameservers._pool import TcpEndpoint


class TLSNameserver(BaseAddressNameserver):
    """TLS 上游解析器（DNS over TLS，utls 握手可伪装 ClientHello 指纹）。"""

    def __init__(self, config: TLSNameserverConfig):
        super().__init__(config)
        self._pool_size = config.pool_size
        self._fingerprint = config.fingerprint
        self._verify = config.verify
        self._ssl_context: SSLContext | None = None
        self._pool: ConnectionPool[TcpEndpoint, TLSStreamConnection] | None = None
        self.host = config.address
        self.port = config.port
        # SNI/验证锚点：显式 server_name 优先；域名地址用地址本身；IP 地址
        # 不发送 SNI（RFC 6066 禁止 literal IP）。
        self._server_hostname = config.server_name
        if self._server_hostname is None:
            text = str(config.address)
            try:
                ip_address(text)
            except ValueError:
                self._server_hostname = text

    def kind(self) -> str:
        return "tls"

    def _build_ssl_context(self) -> SSLContext:
        if self._verify and self._server_hostname is None:
            raise ValueError(
                f"TLS 上游 {self.name} 开启证书校验需要域名地址或显式配置 server_name"
            )
        context = utls.create_default_context()
        if not self._verify:
            context.check_hostname = False
            context.verify_mode = utls.CERT_NONE
        if self._fingerprint is not None:
            # 未知预设抛 ValueError，错误信息列出全部可用预设。
            context.set_fingerprint(self._fingerprint)
        return context

    async def start(self):
        """启动 TLS 上游；pool_size>0 时创建连接池以复用加密连接。"""
        self._ssl_context = self._build_ssl_context()
        if self._pool_size:
            self._pool = ConnectionPool(
                TLSStreamConnectionManager(
                    self._ssl_context,
                    self._server_hostname,
                    connect_timeout=self.timeout,
                ),
                min_idle=1,
                max_size=self._pool_size,
                total_max_size=self._pool_size,
            )
        logger.info(
            "TLS 上游 {} 已启动，目标: {}:{}，指纹: {}",
            self.name,
            self.host,
            self.port,
            self._fingerprint or "标准 ClientHello",
        )

    async def stop(self):
        """停止 TLS 上游，关闭连接池。"""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _query_on_stream(
        self,
        raw_sock: TLSStreamConnection,
        request: dns.message.QueryMessage,
        timeout: float,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        sock = AnyioStreamSocket(raw_sock)
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
                # 连接获取（含新建与握手）计入总时限；0.1 与配置最小超时一致，
                # 避免 0 被 dns.asyncquery 当作立即超时。
                deadline = monotonic() + effective_timeout
                async with self._pool.connection(
                    endpoint, timeout=effective_timeout
                ) as conn:
                    remaining = max(deadline - monotonic(), 0.1)
                    try:
                        return await self._query_on_stream(
                            conn,
                            request,
                            remaining,
                            one_rr_per_rrset,
                            ignore_trailing,
                        )
                    except Exception:
                        # 交换中途失败（如超时打断半条 TLS 记录）后记录层
                        # 对齐不可信，标记脏连接，归还池后由健康检查在
                        # 下次获取时重建。
                        conn.healthy = False
                        raise
            # 无池路径：建连、握手与查询均计入 effective_timeout，黑洞地址
            # 不会挂到 OS 级超时。
            ssl_context = self._ssl_context or self._build_ssl_context()
            deadline = monotonic() + effective_timeout
            conn = await connect_tls(
                str(self.host),
                self.port,
                ssl_context,
                self._server_hostname,
                effective_timeout,
            )
            try:
                return await self._query_on_stream(
                    conn,
                    request,
                    max(deadline - monotonic(), 0.1),
                    one_rr_per_rrset,
                    ignore_trailing,
                )
            finally:
                await conn.aclose()
        except Exception:
            logger.warning("TLS 上游 {} 查询失败", self.name)
            raise
