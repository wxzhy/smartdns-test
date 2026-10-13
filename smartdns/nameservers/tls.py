"""DNS over TLS 上游（utls 握手，可伪装 ClientHello 指纹）。"""

from ipaddress import ip_address
from typing import TYPE_CHECKING

import utls
from loguru import logger

from smartdns.nameservers._stream import StreamNameserver
from smartdns.nameservers._tls import (
    TLSStreamConnection,
    TLSStreamConnectionManager,
    connect_tls,
)

if TYPE_CHECKING:
    from utls import SSLContext

    from smartdns.models.nameserver import TLSNameserverConfig


class TLSNameserver(StreamNameserver):
    """TLS 上游解析器（DNS over TLS，utls 握手可伪装 ClientHello 指纹）。"""

    def __init__(self, config: TLSNameserverConfig):
        super().__init__(config)
        self._fingerprint = config.fingerprint
        self._verify = config.verify
        self._ssl_context: SSLContext | None = None
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

    def _connection_manager(self) -> TLSStreamConnectionManager:
        assert self._ssl_context is not None
        return TLSStreamConnectionManager(
            self._ssl_context, self._server_hostname, connect_timeout=self.timeout
        )

    async def _connect(self, timeout: float) -> TLSStreamConnection:
        ssl_context = self._ssl_context or self._build_ssl_context()
        return await connect_tls(
            str(self.host), self.port, ssl_context, self._server_hostname, timeout
        )

    async def start(self):
        """启动 TLS 上游；pool_size>0 时创建连接池以复用加密连接。"""
        self._ssl_context = self._build_ssl_context()
        await super().start()
        logger.info(
            "TLS 上游 {} 已启动，目标: {}:{}，SNI: {}，指纹: {}，连接池: {}",
            self.name,
            self.host,
            self.port,
            self._server_hostname or "无",
            self._fingerprint or "标准 ClientHello",
            self._pool_size or "关闭",
        )
