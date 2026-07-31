from dns.asyncresolver import Resolver
from dns.rcode import Rcode
from dns.resolver import NXDOMAIN
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.models.resolver import PlainResolverConfig
from smartdns.nameservers.base import BaseNameserver
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.base import BaseResolver


class PlainResolver(BaseResolver, Resolver):
    def __init__(self, config: PlainResolverConfig, nameservers: NameserverManager):
        super(BaseResolver, self).__init__(configure=False)
        super().__init__(config)
        self.config: PlainResolverConfig = config
        self.cache_size = config.cache_size
        self.rotate = config.rotate
        self.edns = config.edns
        self.ecs = config.ecs
        self.lifetime = config.lifetime
        self.raise_on_no_answer = False
        self._upstreams = config.nameservers
        self._manager: NameserverManager = nameservers

    async def start(self):
        """启动解析器"""
        nameservers: list[BaseNameserver] = []
        for name in self._upstreams:
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
        try:
            logger.warning(f"rinfo:{self.timeout},{self.lifetime}")
            answer = await self.resolve(
                request.qname,
                request.rdtype,
                request.rdclass,
                raise_on_no_answer=False,
                lifetime=self.lifetime,
            )
            response = Response.from_answer(answer, upstream=self.config.name)
            return response
        except NXDOMAIN:
            response = Response.from_rcode(Rcode.NXDOMAIN, upstream=self.config.name)
            return response
        except Exception as e:
            logger.exception(
                f"PlainResolver {self.config.name} 解析请求 {request} 时发生错误: {e}"
            )
            response = Response.from_rcode(Rcode.SERVFAIL, upstream=self.config.name)
            return response
