from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartdns.models.context import Request, Response
    from smartdns.models.resolver import BaseResolverConfig


class BaseResolver(ABC):
    def __init__(self, config: BaseResolverConfig):
        self.config = config
        self.name = config.name
        self.timeout = config.timeout

    @abstractmethod
    async def start(self) -> None:
        """启动解析器"""

    @abstractmethod
    async def stop(self) -> None:
        """停止解析器"""

    @abstractmethod
    async def query(self, request: Request) -> Response:
        """解析域名"""
