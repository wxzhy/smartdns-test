from math import isfinite
from threading import BoundedSemaphore
from typing import TYPE_CHECKING

from anyio import create_task_group, sleep
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

# 槽位占满时的等待间隔（秒）：线程信号量无跨线程通知，轮询之间让出事件循环，
# 避免纯 checkpoint 自旋空转 CPU。
_SLOT_POLL_INTERVAL = 0.05


class _GlobalMeasureLimit:
    """在多个 Worker 事件循环之间共享的可取消并发限制。"""

    def __init__(self, value: int) -> None:
        self._semaphore = BoundedSemaphore(value)

    async def acquire(self) -> None:
        # 跨线程 BoundedSemaphore 无事件循环级通知可用，轮询等待是刻意设计；
        # sleep 间隔让出事件循环，避免纯 checkpoint 自旋空转 CPU。
        while not self._semaphore.acquire(  # noqa: ASYNC110
            blocking=False
        ):
            await sleep(_SLOT_POLL_INTERVAL)

    def release(self) -> None:
        self._semaphore.release()

    async def __aenter__(self) -> _GlobalMeasureLimit:
        await self.acquire()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.release()


_MEASURE_LIMIT = _GlobalMeasureLimit(128)


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
        if context.ip_infos is None:
            context.ip_infos = {}
        pending = []
        for info in response.ip_infos:
            if info.ip not in context.ip_infos:
                context.ip_infos[info.ip] = info
                pending.append(info)

        if not self._measure_enabled:
            return

        async def measure(info) -> None:
            try:
                # Worker 运行在多个独立事件循环/线程；使用线程级信号量而非
                # event-loop 绑定的 AnyIO Semaphore，才能提供进程级上限。
                async with _MEASURE_LIMIT:
                    info.rtt = await speedtest(info.ip, self._speedtest)
            except Exception:
                info.rtt = float("inf")

        async with create_task_group() as tg:
            for info in pending:
                tg.start_soon(measure, info)

    async def on_response(self, context: Context) -> None:
        if not context.candidates or not context.ip_infos:
            return
        ranked = sorted(
            ((self._rank(info), info) for info in context.ip_infos.values()),
            key=lambda item: item[0],
        )
        logger.debug("Speedcheck Action {} 排序结果：{}", self.name, ranked)
        (best_missing_rtt, best_rank), best = ranked[0]
        if best.resolver is None:
            return
        candidate = context.candidates.get(best.resolver)
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
