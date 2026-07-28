from typing import TYPE_CHECKING

import dns.asyncquery
import dns.message
from anyio import create_connected_udp_socket
from loguru import logger

from smartdns.nameservers._socket import AnyioDatagramSocket
from smartdns.nameservers.base import BaseNameserver

if TYPE_CHECKING:
    from smartdns.models.nameserver import UDPNameserverConfig


class UDPNameserver(BaseNameserver):
    """UDP解析器类"""

    def __init__(self, config: UDPNameserverConfig):
        super().__init__(config)
        self.host = config.address
        self.port = config.port
        self._repeat = config.repeat
        self._use_tricks = config.use_tricks

    def kind(self) -> str:
        return "udp"

    async def start(self):
        """启动UDP解析器"""
        # 此时不创建socket
        logger.info(f"UDP解析器 {self.name} 已启动，监听地址: {self.host}:{self.port}")

    async def stop(self):
        """停止UDP解析器"""
        logger.info(f"UDP解析器 {self.name} 已停止")

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
        try:
            raw_sock = await create_connected_udp_socket(self.host, self.port)
            sock = AnyioDatagramSocket(
                raw_sock, repeat=self._repeat, use_tricks=self._use_tricks
            )
            return await dns.asyncquery.udp(
                request,
                where=self.address,
                timeout=self.timeout,
                port=self.port,
                sock=sock,
                ignore_unexpected=True,
                ignore_trailing=True,
            )
        except Exception as e:
            logger.exception(f"UDP解析器 {self.name} 查询失败: {e}")
            raise
