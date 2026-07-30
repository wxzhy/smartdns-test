import dns.asyncquery
import dns.message
from anyio import connect_tcp
from loguru import logger

from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers.base import BaseAddressNameserver


class TCPNameserver(BaseAddressNameserver):
    """TCP解析器类"""

    def __init__(self, config):
        super().__init__(config)
        self._pool_size = config.pool_size
        self._pool = None
        self.host = config.address
        self.port = config.port
        self._use_tricks = config.use_tricks

    def kind(self) -> str:
        return "tcp"

    async def start(self):
        """启动TCP解析器"""
        if self._pool_size:
            self._pool = await self._create_pool()
        logger.info(f"TCP解析器 {self.name} 已启动，监听地址: {self.host}:{self.port}")

    async def _connect(self):
        try:
            self._sock = await connect_tcp(self.host, self.port)
        except Exception as e:
            logger.error(f"连接到TCP解析器 {self.name} 失败: {e}")
            raise

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
            raw_sock = await connect_tcp(self.host, self.port)
            sock = AnyioStreamSocket(raw_sock, use_tricks=self._use_tricks)
            return await dns.asyncquery.tcp(
                request,
                where=self.address,
                timeout=self.timeout,
                port=self.port,
                sock=sock,
                ignore_trailing=True,
            )
        except Exception as e:
            logger.exception(f"TCP解析器 {self.name} 查询失败: {e}")
            raise
