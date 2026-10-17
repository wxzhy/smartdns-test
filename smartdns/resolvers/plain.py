"""基于 dnspython 异步 Resolver 的解析器，调度配置中的自定义 Nameserver。"""

from time import time
from typing import TYPE_CHECKING, cast

import dns.rdatatype
from dns.asyncresolver import Resolver
from dns.edns import ECSOption
from dns.exception import DNSException
from dns.rcode import Rcode
from dns.resolver import NXDOMAIN, Answer
from loguru import logger

from smartdns.actions._helper import replay_answer
from smartdns.models.context import EDNS_PAYLOAD, Request, Response
from smartdns.resolvers.base import BaseResolver
from smartdns.utils.cache_async import AnswerCache

if TYPE_CHECKING:
    from dns.message import QueryMessage
    from dns.name import Name
    from dns.rdataclass import RdataClass
    from dns.rdatatype import RdataType

    from smartdns.models.context import Context
    from smartdns.models.resolver import PlainResolverConfig
    from smartdns.nameservers.base import BaseNameserver
    from smartdns.nameservers.manager import NameserverManager

type ResolverCacheKey = tuple[Name, RdataType, RdataClass]


class PlainResolver(BaseResolver, Resolver):
    def __init__(self, config: PlainResolverConfig, nameservers: NameserverManager):
        # 两基类 __init__ 签名不同：先初始化 dnspython Resolver（configure=False，
        # 不读系统 DNS 配置），再初始化 BaseResolver；顺序依赖 MRO。
        super(BaseResolver, self).__init__(configure=False)
        super().__init__(config)
        self.config: PlainResolverConfig = config
        self.rotate = config.rotate
        self.edns = config.edns
        self.payload = EDNS_PAYLOAD
        if config.ecs is not None:
            self.ednsoptions = [
                ECSOption(str(config.ecs.network_address), config.ecs.prefixlen)
            ]
        self.lifetime = config.lifetime
        self._nodata_ttl = config.nodata_ttl
        self._upstreams = config.nameservers
        self._manager: NameserverManager = nameservers
        upstreams: list[BaseNameserver] = []
        for name in self._upstreams:
            ns = self._manager.get(name)
            if ns is not None:
                upstreams.append(ns)
            else:
                logger.warning("Nameserver {} 不存在", name)
        self.nameservers = upstreams
        # dnspython 用 timeout 作为单次尝试上限：等于 lifetime 时首个上游黑洞
        # 就会耗尽全部时限，开启 rotate 后一个上游故障即令约一半查询失败。
        if config.timeout is None:
            self.timeout = self.lifetime / max(1, len(upstreams))
        elif config.timeout >= self.lifetime and len(upstreams) > 1:
            logger.warning(
                "PlainResolver {} 的 timeout({}) 不小于 lifetime({})，"
                "首个上游无应答时无法切换到其他上游",
                self.name,
                config.timeout,
                self.lifetime,
            )
        # 应答缓存（AnswerCache）：相同完整配置跨 Worker 线程共享；同名但配置
        # 不同的解析器彼此隔离。cache_size=0 关闭；fetch 的同键 in-flight
        # 合并按事件循环隔离。
        if config.cache_size > 0:
            self._cache: AnswerCache[ResolverCacheKey, Answer] | None = (
                AnswerCache.shared(
                    f"plain:{config.model_dump_json()}", config.cache_size
                )
            )
        else:
            self._cache = None

    async def start(self):
        """启动解析器"""

        logger.info(
            "PlainResolver {} 启动成功，上游数: {}，缓存容量: {}",
            self.name,
            len(self.nameservers),
            self.config.cache_size,
        )

    async def stop(self):
        """停止解析器"""
        self.nameservers = []
        logger.info("PlainResolver {} 停止成功", self.name)

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """解析域名"""
        try:
            if self._cache is None:
                answer = await self._resolve_answer(
                    request.qname, request.rdtype, request.rdclass
                )
            else:
                answer = await self._cache.fetch(
                    (request.qname, request.rdtype, request.rdclass),
                    lambda: self._resolve_answer(
                        request.qname, request.rdtype, request.rdclass
                    ),
                )
            # 复制回放：命中时 RRset TTL 须按剩余生存期衰减，缓存内原始
            # Answer 不外泄给调用方。
            return Response.from_answer(replay_answer(answer), upstream=self.name)
        except NXDOMAIN:
            return Response.from_rcode(Rcode.NXDOMAIN, upstream=self.name)
        except DNSException as error:
            # 超时、上游全部失败等属常规故障，记一行警告即可，不打印堆栈。
            logger.warning(
                "PlainResolver {} 解析 {} 失败: {}: {}",
                self.name,
                request.qname,
                type(error).__name__,
                error,
            )
            return Response.servfail(self.name)
        except Exception:
            logger.exception("PlainResolver {} 解析 {} 出错", self.name, request.qname)
            return Response.servfail(self.name)

    async def _resolve_answer(
        self, qname: Name, rdtype: RdataType, rdclass: RdataClass
    ) -> Answer:
        """单次上游解析；NXDOMAIN 携带权威 SOA 时转为可缓存的负应答对象。"""
        try:
            answer = await self.resolve(
                qname,
                rdtype,
                rdclass,
                raise_on_no_answer=False,
                lifetime=self.lifetime,
            )
        except NXDOMAIN as error:
            answer = self._nxdomain_answer(error, qname, rdtype, rdclass)
            if answer is not None:
                self._clamp_nodata_expiration(answer)
                return answer
            raise
        self._clamp_nodata_expiration(answer)
        return answer

    def _clamp_nodata_expiration(self, answer: Answer) -> None:
        """无记录且无 SOA 的否定应答显式设置负缓存 TTL。

        dnspython 的 resolve_chaining 找不到 SOA 时 minimum_ttl 取 MAX_TTL
        （约 136 年），此类 NODATA/NXDOMAIN 进入缓存后永不过期；
        携带 SOA 的负应答已按 min(SOA TTL, SOA.minimum) 计算，不在此列。
        """
        if answer.rrset is not None:
            return
        if any(
            rrset.rdtype == dns.rdatatype.SOA for rrset in answer.response.authority
        ):
            return
        # CNAME 链本身可能有比负缓存上限更短的 TTL，不能将其延长。
        answer.expiration = min(answer.expiration, time() + self._nodata_ttl)

    def _nxdomain_answer(
        self, error: NXDOMAIN, qname: Name, rdtype: RdataType, rdclass: RdataClass
    ) -> Answer | None:
        """从 NXDOMAIN 异常中提取携带 SOA 的应答报文。

        dnspython 把各次尝试的响应报文放在异常 kwargs 的 responses
        （qname -> Message）；authority 区的 SOA 供客户端负缓存使用。
        """
        responses = error.kwargs.get("responses") or {}
        message = responses.get(qname)
        if message is None and responses:
            message = next(reversed(list(responses.values())))
        if message is None:
            return None
        return Answer(
            qname,
            rdtype,
            rdclass,
            cast("QueryMessage", message),
            str(self.nameservers[0]) if self.nameservers else None,
        )
