from dns.asyncresolver import Resolver
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.models.resolver import PlainResolverConfig
from smartdns.nameservers.base import BaseNameserver
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.base import BaseResolver


class PlainResolver(BaseResolver, Resolver):
    def __init__(self, config: PlainResolverConfig, nameservers: NameserverManager):
        super().__init__(config)
        super(BaseResolver, self).__init__(configure=False)
        self.config: PlainResolverConfig = config
        self.cache_size = self.config.cache_size
        self.rotate = self.config.rotate
        self.edns = self.config.edns
        self.ecs = self.config.ecs
        self.lifetime = self.config.lifetime
        self._manager: NameserverManager = nameservers

    async def start(self):
        """启动解析器"""
        nameservers: list[BaseNameserver] = []
        for name in self.config.nameservers:
            ns = self._manager.get(name)
            if ns is not None:
                nameservers.append(ns)
            else:
                logger.warning(f"Nameserver {name} 不存在")
        self.nameservers = nameservers
        logger.info(
            f"PlainResolver {self.config.name} 启动成功，使用的上游DNS服务器: {self.nameservers}"
        )

    async def stop(self):
        """停止解析器"""
        self.nameservers = []
        logger.info(f"PlainResolver {self.config.name} 停止成功")

    async def query(self, request: Request) -> Response:
        """解析域名"""
        answer = await self.resolve(request.qname, request.rdtype, request.rdclass)
        response = Response.from_answer(answer, upstream=self.config.name)
        return response
