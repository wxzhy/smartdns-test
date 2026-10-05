from math import isfinite
from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from loguru import logger

from smartdns.actions._helper import replace_response_ipinfo
from smartdns.actions._ping import speedtest
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_response

if TYPE_CHECKING:
    from smartdns.models.action import SpeedcheckActionConfig
    from smartdns.models.context import Context, Response
    from smartdns.models.geodata import IPInfo


class SpeedcheckAction(BaseAction):
    """优先选择有有效 RTT 的 IP；没有有效 RTT 时按标签/ASN 倍率排序。"""

    def __init__(self, config: SpeedcheckActionConfig) -> None:
        super().__init__(config)
        self._speedtest = config.ping_config
        self._measure_enabled = self._speedtest.ping or bool(self._speedtest.port)
        self._matcher = config.match_ip
        self._tag_multipliers = dict(config.tag_multipliers)
        self._asn_multipliers = dict(config.asn_multipliers)
        self._num = config.max_num
        self._threshold = config.threshold

    def _multiplier(self, info: IPInfo) -> float:
        """标签优先于 ASN；多个标签命中时以配置顺序确定倍率。"""
        for tag, multiplier in self._tag_multipliers.items():
            if info.country and tag in info.country:
                return multiplier
        if info.asn is not None:
            return self._asn_multipliers.get(info.asn, 1.0)
        return 1.0

    def _rank(self, info: IPInfo) -> tuple[bool, float]:
        """有有效 RTT 的 IP 排在前面；无有效 RTT 的 IP 按倍率排序。"""
        multiplier = self._multiplier(info)
        if info.rtt is not None and isfinite(info.rtt):
            return False, info.rtt * multiplier
        return True, multiplier

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

        async def measure(info) -> None:
            try:
                # 相同 IP 的候选各自取得完整 RTT；speedtest 合并实际探测，
                # 候选不能因另一个上游尚在测速而跳过等待。
                info.rtt = await speedtest(info.ip, self._speedtest)
            except Exception:
                info.rtt = float("inf")

        if self._measure_enabled:
            async with create_task_group() as tg:
                for info in response.ip_infos:
                    tg.start_soon(measure, info)
        # 整个候选完成测速后再发布，取消的候选不会留下半完成的 IP 信息。
        if context.ip_infos is None:
            context.ip_infos = {}
        for info in response.ip_infos:
            context.ip_infos[info.ip] = info

    async def on_response(self, context: Context) -> None:
        if not context.candidates or not context.ip_infos:
            return
        candidates = {
            name: candidate
            for name, candidate in context.candidates.items()
            if not candidate.invalid
            and candidate.rcode == Rcode.NOERROR
            and candidate.ans is not None
        }
        valid_ips = {
            (name, info.ip)
            for name, candidate in candidates.items()
            for info in candidate.ip_infos or ()
        }
        available = {
            ip: info
            for ip, info in context.ip_infos.items()
            if (info.resolver, ip) in valid_ips
        }
        # 同 IP 的后到候选可能在发布应答前被取消；保留已完成候选自己的信息。
        for candidate in candidates.values():
            for info in candidate.ip_infos or ():
                if info.ip in context.ip_infos:
                    available.setdefault(info.ip, info)
        if not available:
            return
        ranked = sorted(
            ((self._rank(info), info) for info in available.values()),
            key=lambda item: item[0],
        )
        logger.debug("Speedcheck Action {} 排序结果：{}", self.name, ranked)
        (best_missing_rtt, best_rank), best = ranked[0]
        if best.resolver is None:
            return
        candidate = candidates.get(best.resolver)
        if candidate is None:
            return
        selected = {}
        for (missing_rtt, rank), info in ranked:
            if not best_missing_rtt and (
                missing_rtt
                or info.country != best.country
                or rank - best_rank > self._threshold
            ):
                continue
            selected[info.ip] = info
            if len(selected) >= self._num:
                break
        if selected:
            context.response = replace_response_ipinfo(candidate, selected)
