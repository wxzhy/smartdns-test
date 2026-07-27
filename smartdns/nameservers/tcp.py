import dns.message
from anyio import connect_tcp
from loguru import logger

from smartdns.nameservers.base import BaseNameserver


class TCPNameserver(BaseNameserver):
    """TCP解析器类"""

    def __init__(self, config):
        super().__init__(config)
        self._pool_size = config.pool_size
        self._pool = None
        self._sock = None
        self.host = config.host
        self.port = config.port

    def kind(self) -> str:
        return "tcp"

    async def start(self):
        """启动TCP解析器"""
        if self._pool_size:
            self._pool = await self._create_pool()
        else:
            self._sock = await self._connect()
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
        raise NotImplementedError
