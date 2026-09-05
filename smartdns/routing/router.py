from typing import TYPE_CHECKING

from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Context, Response
from smartdns.routing.matcher import match_request

if TYPE_CHECKING:
    from smartdns.actions.manager import ActionManager
    from smartdns.models.rule import Rule
    from smartdns.resolvers.base import BaseResolver
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
                if action is not None:
                    self.before.append(action)
        if config.after:
            for action_name in config.after:
                action = self._actions.get(action_name)
                if action is not None:
                    self.after.append(action)
        if self._upstream:
            self.resolver = self._resolvers.get(self._upstream)
            if self.resolver is None:
                logger.warning(
                    "路由 {} 的上游解析器 {} 不存在",
                    self.config.name,
                    self._upstream,
                )
        logger.info("启动路由 {}，上游: {}", self.config.name, self._upstream)

    def match(self, context: Context) -> bool:
        """判断请求是否匹配本路由规则。"""
        matcher = self._matcher
        if matcher is None:
            return True
        return match_request(matcher, context.request)

    async def query(self, context: Context) -> bool:
        """按规则处理请求：before 动作 → resolver → after 动作 → 子查询。

        返回 True 表示本路由已产出最终应答（停止后续路由）；
        返回 False 表示本路由未处理（交由后续路由）。
        """
        if not self.match(context):
            return False
        request = context.request
        for action in self.before:
            await action.on_request(context)
            if context.stop:
                return True
        if self.resolver is not None:
            context.response = await self.resolver.query(request, context)
        if context.response is None:
            # 无 resolver 或未产出应答：交后续路由，避免黑洞式吞掉请求。
            return False
        if context.response.rcode != Rcode.NOERROR:
            # 权威否定/失败应答（NXDOMAIN 等）作为最终结果，跳过 after 动作。
            return True
        for action in self.after:
            await action.on_response(context)
            if context.stop:
                return True
        if context.subquery is not None:
            if self.resolver is None:
                logger.debug("路由 {} 无上游解析器，忽略子查询", self.config.name)
            else:
                await self._run_subquery(context, context.subquery, self.resolver)
        return True

    async def _run_subquery(
        self, context: Context, subquery: Context, resolver: BaseResolver
    ) -> None:
        """执行 on_response 阶段设置的子查询，并把结果交给 after 动作。

        以 context=None 调用 resolver，ConcurrentResolver 会因此跳过
        on_resolver 动作与候选收集，子查询不重复外层的加工逻辑；
        只执行一轮，on_subquery 中再设置 context.subquery 不会再次触发。
        """
        try:
            subquery.response = await resolver.query(subquery.request, None)
        except Exception:
            logger.warning(
                "路由 {} 的子查询 {} 失败", self.config.name, subquery.request.qname
            )
            subquery.response = Response.from_rcode(
                Rcode.SERVFAIL, upstream=self._upstream or ""
            )
        for action in self.after:
            await action.on_subquery(context, subquery.response)
            if context.stop:
                break
