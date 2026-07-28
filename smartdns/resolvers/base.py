from smartdns.models.context import Request, Response
from smartdns.models.resolver import BaseResolverConfig


class BaseResolver:
    def __init__(self, config: BaseResolverConfig):
        self.config = config
        self.name = config.name
        self.timeout = config.timeout

    async def start(self):
        """启动解析器"""
        raise NotImplementedError

    async def stop(self):
        """停止解析器"""
        raise NotImplementedError

    async def query(self, request: Request) -> Response:
        """解析域名"""
        raise NotImplementedError
