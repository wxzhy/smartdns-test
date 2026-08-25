from typing import TYPE_CHECKING, cast

from dns.asyncresolver import Resolver
from dns.edns import ECSOption
from dns.rcode import Rcode
from dns.resolver import NXDOMAIN, Answer
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.models.context import Context
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
        self.payload = 1232
        if config.ecs is not None:
            self.ednsoptions = [
                ECSOption(str(config.ecs.network_address), config.ecs.prefixlen)
            ]
        self.lifetime = config.lifetime
        self._upstreams = config.nameservers
        self._manager: NameserverManager = nameservers
        upstreams: list[BaseNameserver] = []
        for name in self._upstreams:
            ns = self._manager.get(name)
            if ns is not None:
                upstreams.append(ns)
            else:
                logger.warning(f"Nameserver {name} 不存在")
        self.nameservers = upstreams

    async def start(self):
        """启动解析器"""

        logger.info(
            f"PlainResolver {self.name} 启动成功，上游数: {len(self.nameservers)}"
        )

    async def stop(self):
        """停止解析器"""
        self.nameservers = []
        logger.info(f"PlainResolver {self.name} 停止成功")

    async def query(self, request: Request, context: Context | None = None) -> Response:
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
        except NXDOMAIN as error:
            answer = self._nxdomain_answer(error, request)
            if answer is not None:
                return Response.from_answer(answer, upstream=self.name)
            return Response.from_rcode(Rcode.NXDOMAIN, upstream=self.name)
        except Exception:
            logger.exception(f"PlainResolver {self.name} 解析请求失败")
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

    def _nxdomain_answer(self, error: NXDOMAIN, request: Request) -> Answer | None:
        """从 NXDOMAIN 异常中提取携带 SOA 的应答报文。

        dnspython 把各次尝试的响应报文放在异常 kwargs 的 responses
        （qname -> Message）；authority 区的 SOA 供客户端负缓存使用。
        """
        responses = error.kwargs.get("responses") or {}
        message = responses.get(request.qname)
        if message is None and responses:
            message = next(reversed(list(responses.values())))
        if message is None:
            return None
        return Answer(
            request.qname,
            request.rdtype,
            request.rdclass,
            cast("QueryMessage", message),
            str(self.nameservers[0]) if self.nameservers else None,
        )
