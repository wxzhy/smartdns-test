from typing import TYPE_CHECKING

from dns.rcode import Rcode
from dns.rdatatype import to_text
from loguru import logger

if TYPE_CHECKING:
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
            if self.resolver is None:
                logger.warning(
                    f"路由 {self.config.name} 的上游解析器 {self._upstream} 不存在"
                )
        logger.info(f"启动路由 {self.config.name}，上游: {self._upstream}")

    def match(self, context: Context) -> bool:
        """判断请求是否匹配本路由规则。"""
        matcher = self._matcher
        if matcher is None:
            return True
        request = context.request
        if matcher.query_types is not None:
            query_type = to_text(request.rdtype).upper()
            if query_type not in {qt.upper() for qt in matcher.query_types}:
                logger.debug(f"路由 {self.config.name} 不匹配查询类型 {query_type}")
                return False
        country = request.name_info.country
        # domain_include 为 fail-closed：无法确认归属（含无 geo 数据）则不匹配。
        if matcher.domain_include is not None and (
            country is None or not (country & matcher.domain_include)
        ):
            logger.debug(
                f"路由 {self.config.name} 域名 {request.qname} 不在 domain_include"
            )
            return False
        if (
            matcher.domain_exclude is not None
            and country is not None
            and country & matcher.domain_exclude
        ):
            logger.debug(
                f"路由 {self.config.name} 域名 {request.qname} 命中 domain_exclude"
            )
            return False
        return True

    async def query(self, context: Context) -> bool:
        """按规则处理请求：before 动作 → resolver → after 动作。

        返回 True 表示本路由已产出最终应答（停止后续路由）；
        返回 False 表示本路由未处理（交由后续路由）。
        """
        if not self.match(context):
            return False
        request = context.request
        logger.debug(f"路由 {self.config.name} 匹配 {request.qname}")
        for action in self.before:
            await action.on_request(context)
            if context.stop:
                logger.debug(f"路由 {self.config.name} 在 before 阶段停止")
                return True
        if self.resolver is not None:
            context.response = await self.resolver.query(request)
        if context.response is None:
            # 无 resolver 或未产出应答：交后续路由，避免黑洞式吞掉请求。
            logger.debug(f"路由 {self.config.name} 未产出应答，交后续路由")
            return False
        if context.response.rcode != Rcode.NOERROR:
            # 权威否定/失败应答（NXDOMAIN 等）作为最终结果，跳过 after 动作。
            return True
        for action in self.after:
            await action.on_response(context)
            if context.stop:
                logger.debug(f"路由 {self.config.name} 在 after 阶段停止")
                return True
        return True
