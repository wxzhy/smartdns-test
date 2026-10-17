"""路由规则执行器：匹配请求后依次运行 before 动作、解析器、after 动作与子查询。"""

from typing import TYPE_CHECKING

from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Context, Response
from smartdns.routing.matcher import match_request
from smartdns.utils.deadline import response_scope

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from smartdns.actions.manager import ActionManager
    from smartdns.models.rule import Rule
    from smartdns.resolvers.base import BaseResolver
    from smartdns.resolvers.manager import ResolverManager


class Router:
    def __init__(
        self,
        config: Rule,
        resolvers: ResolverManager,
        actions: ActionManager,
        subquery_handler: Callable[[Context], Awaitable[None]] | None = None,
    ):
        self.config = config
        self._subquery_handler = subquery_handler
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
        logger.debug(
            "路由 {} 命中 {} {}", self.config.name, request.qname, request.rdtype.name
        )
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
        # 后处理/子查询到期时保留最后一个完整应答，给 Master 和监听器留出回包时间。
        with response_scope(request, response_ready=True):
            for action in self.after:
                await action.on_response(context)
                if context.stop:
                    return True
            if context.subquery is not None and not context.is_subquery:
                if self.resolver is None and self._subquery_handler is None:
                    logger.debug("路由 {} 无上游解析器，忽略子查询", self.config.name)
                else:
                    await self._run_subquery(context, context.subquery, self.resolver)
        return True

    async def _run_subquery(
        self, context: Context, subquery: Context, resolver: BaseResolver | None
    ) -> None:
        """执行 on_response 阶段设置的子查询，并把结果交给 after 动作。

        Worker 提供的 handler 复用完整路由与 Master 最终缓存；独立 Router
        则按本规则加工。子查询只执行一层，同一目标/类型避免等待自身的缓存任务。
        """
        try:
            same_query = (
                subquery.request.qname == context.request.qname
                and subquery.request.rdtype == context.request.rdtype
                and subquery.request.rdclass == context.request.rdclass
            )
            if self._subquery_handler is not None and not same_query:
                await self._subquery_handler(subquery)
            elif resolver is not None:
                subquery.response = await resolver.query(subquery.request, subquery)
                if subquery.response.rcode == Rcode.NOERROR:
                    for action in self.after:
                        await action.on_response(subquery)
                        if subquery.stop:
                            break
            if subquery.response is None:
                subquery.response = Response.servfail()
        except Exception:
            logger.warning(
                "路由 {} 的子查询 {} 失败", self.config.name, subquery.request.qname
            )
            subquery.response = Response.servfail(self._upstream or "")
        for action in self.after:
            await action.on_subquery(context, subquery.response)
            if context.stop:
                break
