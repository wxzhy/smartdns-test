from dns.rcode import Rcode
from loguru import logger
from smartdns.models.rule import Rule
from smartdns.resolvers.manager import ResolverManager
from smartdns.models.context import Context, Request, Response
from dns.rdatatype import to_text


class Router:
    def __init__(self, config: Rule, resolvers: ResolverManager):
        self.config = config
        self._resolvers = resolvers
        self._upstream = config.resolver
        self.resolver = None
        self.domain_include: set[str] | None = config.domain_include
        self.domain_exclude: set[str] | None = config.domain_exclude
        self.query_types = config.query_types
        if self._upstream:
            self.resolver = self._resolvers.get(self._upstream)
        logger.info(f"启动 {self.config.name} resolver名称:{self._upstream}")

    async def query(self, context: Context) -> bool:
        if self.resolver:
            request = context.request
            query_type = to_text(request.rdtype)
            if self.query_types is not None and query_type not in self.query_types:
                logger.debug(f"路由 {self.config.name} 不匹配查询类型 {query_type}")
                return False
            if request.name_info.country is not None:
                if (
                    self.domain_include is not None
                    and not request.name_info.country & self.domain_include
                ):
                    logger.debug(f"路由 {self.config.name} 不匹配域名 {request.qname}")
                    return False
                if (
                    self.domain_exclude is not None
                    and request.name_info.country & self.domain_exclude
                ):
                    logger.debug(f"路由 {self.config.name} 不匹配域名 {request.qname}")
                    return False
            try:
                context.response = await self.resolver.query(request)
                return True
            except Exception as e:
                logger.error(f"路由 {self.config.name} 查询失败: {e}")
                context.response = Response.from_rcode(
                    Rcode.SERVFAIL, upstream=self.config.name
                )
                return True
        else:
            logger.warning(f"路由 {self.config.name} 没有配置解析器")
            return False
