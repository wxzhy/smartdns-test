"""过滤 Action：丢弃 IP 命中排除标签的候选应答（常用于识别污染结果）。"""

from typing import TYPE_CHECKING

from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context, match_response

if TYPE_CHECKING:
    from smartdns.models.action import FilterActionConfig, FilterItem
    from smartdns.models.context import Context, Response


class FilterAction(BaseAction):
    """Filter Action 类。

    在 ConcurrentResolver 的 on_resolver 阶段，把命中排除标签的候选
    标记为 invalid，使其在竞速选择和候选收集中被丢弃。
    """

    def __init__(self, config: FilterActionConfig) -> None:
        super().__init__(config)
        # 深拷贝配置条目后再限定查询类型，避免原地修改多 Worker 共享的配置对象。
        self.map: list[FilterItem] = [
            item.model_copy(deep=True) for item in config.filters
        ]
        for item in self.map:
            item.match_name.query_types = {"A", "AAAA", "HTTPS"}

    async def start(self) -> None:
        logger.info("Filter Action {} 已启动，映射数={}", self.name, len(self.map))

    async def on_resolver(self, context: Context, response: Response) -> None:
        """转发到 resolver 之后调用，把命中排除标签的候选标记为 invalid。"""
        logger.debug(
            "Filter Action {} on_resolver: rcode={}, upstream={}",
            self.name,
            response.rcode,
            response.upstream,
        )
        # 临时挂载当前候选，让 match_context 匹配其 CNAME 链（同 ReplaceAction）。
        original = context.response
        context.response = response
        try:
            # 返回类型和请求类型不符
            if (
                response.ans is not None
                and response.ans.rdtype != context.request.rdtype
            ):
                self._reject(context, response, "记录类型与请求不符")
                return
            for index, item in enumerate(self.map):
                if not match_context(item.match_name, context):
                    continue
                if not match_response(item.match_ip, response):
                    self._reject(context, response, f"命中第 {index + 1} 条过滤项")
                    return
        finally:
            context.response = original

    def _reject(self, context: Context, response: Response, reason: str) -> None:
        response.invalid = True
        logger.debug(
            "Filter Action {}：丢弃 {} 来自 {} 的候选（{}）: {}",
            self.name,
            context.request.qname,
            response.upstream,
            reason,
            response.ip_list,
        )
