from typing import TYPE_CHECKING

from dns.rdatatype import RdataType
from loguru import logger

from smartdns.actions._helper import replace_response_ip
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context

if TYPE_CHECKING:
    from smartdns.models.action import FallbackActionConfig, FallbackMap
    from smartdns.models.context import Context


class FallbackAction(BaseAction):
    """当无可用 IP（NODATA 空应答）或全部测速失败时以静态地址替换当前响应。"""

    def __init__(self, config: FallbackActionConfig) -> None:
        super().__init__(config)
        # 深拷贝配置条目后再限定查询类型，避免原地修改多 Worker 共享的配置对象。
        self.map: list[FallbackMap] = [
            item.model_copy(deep=True) for item in config.map
        ]
        for item in self.map:
            item.match_name.query_types = {"A", "AAAA"}

    async def start(self) -> None:
        logger.info("Fallback Action {} 已启动，映射数={}", self.name, len(self.map))

    async def on_response(self, context: Context) -> None:
        # NOERROR 但无 IP（NODATA 空应答）视为没有可用 IP，交由静态映射回退。
        if context.response is None:
            return
        # 未测速的 IP 仍是可用候选，例如 speedcheck 仅按倍率排序的模式。
        if context.ip_infos and any(
            info.rtt is None or info.rtt < float("inf")
            for info in context.ip_infos.values()
        ):
            return
        for item in self.map:
            if not match_context(item.match_name, context):
                continue
            if context.request.rdtype == RdataType.A and item.ipv4:
                context.response = replace_response_ip(
                    context.response, item.ipv4, item.ttl
                )
            elif context.request.rdtype == RdataType.AAAA and item.ipv6:
                context.response = replace_response_ip(
                    context.response, item.ipv6, item.ttl
                )
            return
