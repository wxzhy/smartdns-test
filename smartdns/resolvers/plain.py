from typing import TYPE_CHECKING

from dns.asyncresolver import Resolver
from dns.rcode import Rcode
from dns.resolver import NXDOMAIN
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.models.resolver import PlainResolverConfig
    from smartdns.nameservers.base import BaseNameserver
    from smartdns.nameservers.manager import NameserverManager


class PlainResolver(BaseResolver, Resolver):
    def __init__(self, config: PlainResolverConfig, nameservers: NameserverManager):
        # 两基类 __init__ 签名不同：先初始化 dnspython Resolver（configure=False，
        # 不读系统 DNS 配置），再初始化 BaseResolver；顺序依赖 MRO。
        super(BaseResolver, self).__init__(configure=False)
        super().__init__(config)
        self.config: PlainResolverConfig = config
        self.rotate = config.rotate
        self.edns = config.edns
        self.lifetime = config.lifetime
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
            f"PlainResolver {self.name} 启动成功，上游数: {len(self.nameservers)}"
        )

    async def stop(self):
        """停止解析器"""
        self.nameservers = []
        logger.info(f"PlainResolver {self.name} 停止成功")

    async def query(self, request: Request) -> Response:
        """解析域名"""
        try:
            answer = await self.resolve(
                request.qname,
                request.rdtype,
                request.rdclass,
                raise_on_no_answer=False,
                lifetime=self.lifetime,
            )
            return Response.from_answer(answer, upstream=self.name)
        except NXDOMAIN:
            return Response.from_rcode(Rcode.NXDOMAIN, upstream=self.name)
        except Exception:
            logger.exception(f"PlainResolver {self.name} 解析请求失败")
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
