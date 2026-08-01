from dns.rcode import Rcode
from dns.rdatatype import to_text
from loguru import logger

from smartdns.actions.manager import ActionManager
from smartdns.models.context import Context
from smartdns.models.rule import Rule
from smartdns.resolvers.manager import ResolverManager


class Router:
    def __init__(
        self, config: Rule, resolvers: ResolverManager, actions: ActionManager
    ):
        self.config = config
        self._resolvers = resolvers
        self._actions = actions
        self._upstream = config.resolver
        self.resolver = None
        self._matcher = config.matcher
        self.before, self.after = [], []
        if config.before:
            for action_name in config.before:
                action = self._actions.get(action_name)
                if action:
                    self.before.append(action)
        if config.after:
            for action_name in config.after:
                action = self._actions.get(action_name)
                if action:
                    self.after.append(action)
        if self._upstream:
            self.resolver = self._resolvers.get(self._upstream)
        logger.info(f"启动 {self.config.name} resolver名称:{self._upstream}")

    async def match(self, context: Context) -> bool:
        """匹配请求上下文是否符合路由规则"""
        if not self._matcher:
            logger.debug(f"路由 {self.config.name} 没有匹配器，默认匹配所有请求")
            return True
        request = context.request
        query_type = to_text(request.rdtype)
        if (
            self._matcher.query_types is not None
            and query_type not in self._matcher.query_types
        ):
            logger.debug(f"路由 {self.config.name} 不匹配查询类型 {query_type}")
            return False
        if request.name_info.country is not None:
            if (
                self._matcher.domain_include is not None
                and not request.name_info.country & self._matcher.domain_include
            ):
                logger.debug(f"路由 {self.config.name} 不匹配域名 {request.qname}")
                return False
            if (
                self._matcher.domain_exclude is not None
                and request.name_info.country & self._matcher.domain_exclude
            ):
                logger.debug(f"路由 {self.config.name} 不匹配域名 {request.qname}")
                return False
        return True

    async def query(self, context: Context) -> bool:
        """处理请求上下文"""
        if await self.match(context):
            logger.info(f"路由 {self.config.name} 匹配请求 {context.request}")
            for action in self.before:
                await action.on_request(context)
                if context.stop:
                    logger.info(
                        f"路由 {self.config.name} 在 before 阶段停止请求 {context.request}"
                    )
                    return True
            if self.resolver is not None:
                context.response = await self.resolver.query(context.request)
            if (
                not context.response
                or context.response.rcode != Rcode.NOERROR
                or context.stop
            ):
                logger.info(
                    f"路由 {self.config.name} 在 resolver 阶段停止请求 {context.request}"
                )
                return True
            for action in self.after:
                await action.on_response(context)
                if context.stop:
                    logger.info(
                        f"路由 {self.config.name} 在 after 阶段停止请求 {context.request}"
                    )
                    return True
            return True
        return False
