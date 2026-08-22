from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rdatatype import RdataType
from loguru import logger

from smartdns.actions._helper import replace_response_ipinfo
from smartdns.actions._ping import speedtest
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_response

if TYPE_CHECKING:
    from smartdns.models.action import SpeedcheckConfig
    from smartdns.models.context import Context, Response


class SpeedcheckAction(BaseAction):
    """对候选 IP 测速，并用最佳候选的复制结果作为最终响应。"""

    def __init__(self, config: SpeedcheckConfig) -> None:
        super().__init__(config)
        self._speedtest = config.ping_config
        self._matcher = config.match_ip
        self._num = config.max_num
        self._threshold = config.threshold

    async def start(self) -> None:
        logger.info("Speedcheck Action {} 已启动", self.name)

    async def on_resolver(self, context: Context, response: Response) -> None:
        if (
            response.ans is None
            or response.ans.rdtype not in (RdataType.A, RdataType.AAAA)
            or not response.ip_infos
            or not match_response(self._matcher, response)
        ):
            return
        if context.ip_infos is None:
            context.ip_infos = {}
        pending = []
        for info in response.ip_infos:
            if info.ip not in context.ip_infos:
                context.ip_infos[info.ip] = info
                pending.append(info)

        async def measure(info) -> None:
            try:
                info.rtt = await speedtest(info.ip, self._speedtest)
            except Exception:
                info.rtt = float("inf")

        async with create_task_group() as tg:
            for info in pending:
                tg.start_soon(measure, info)

    async def on_response(self, context: Context) -> None:
        if not context.candidates or not context.ip_infos:
            return
        infos = sorted(
            context.ip_infos.values(),
            key=lambda info: info.rtt if info.rtt is not None else float("inf"),
        )
        logger.debug("Speedcheck Action {} 测速结果：{}", self.name, infos)
        best = infos[0]
        if best.rtt is None or best.rtt == float("inf") or best.resolver is None:
            return
        candidate = context.candidates.get(best.resolver)
        if candidate is None:
            return
        selected = {}
        for info in infos:
            if info.country != best.country:
                continue
            if info.rtt is None or info.rtt - best.rtt > self._threshold:
                continue
            selected[info.ip] = info
            if len(selected) >= self._num:
                break
        if selected:
            context.response = replace_response_ipinfo(candidate, selected)
