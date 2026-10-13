"""解析器基类。"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartdns.models.context import Context, Request, Response
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
    async def query(self, request: Request, context: Context | None = None) -> Response:
        """解析域名。

        context 供需要向全局上下文写回中间结果的解析器使用（如 ConcurrentResolver
        的候选应答列表）；不关心上下文的解析器忽略该参数即可。
        """
