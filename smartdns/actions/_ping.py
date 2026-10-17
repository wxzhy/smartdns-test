"""IP 测速：ICMP/TCP 建连探测、结果缓存与全进程并发上限。"""

from __future__ import annotations

from time import perf_counter
from typing import TYPE_CHECKING

from anyio import connect_tcp, create_task_group, fail_after
from icmplib import async_ping
from loguru import logger

from smartdns.utils.cache_async import CacheSlot, cached
from smartdns.utils.concurrency import GlobalCapacityLimiter

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from ipaddress import IPv4Address, IPv6Address

    from smartdns.models.action import PingConfig

SpeedtestKey = tuple[str, bool, bool, tuple[int, ...], float]


# 测速结果缓存（RTT 毫秒）由 Master 启动时绑定，全部 Worker 共享。
SPEEDTEST_CACHE: CacheSlot[SpeedtestKey, float] = CacheSlot()
set_cache = SPEEDTEST_CACHE.bind
_MEASURE_LIMIT = GlobalCapacityLimiter(128)


def _speedtest_key(
    ip: str | IPv4Address | IPv6Address, config: PingConfig
) -> SpeedtestKey:
    return (
        str(ip),
        config.ping,
        config.privileged,
        tuple(sorted(config.port or set())),
        config.timeout,
    )


async def ping(ip: str, timeout: float = 1.0, privileged: bool = False) -> float | None:
    """ICMP 测速，返回毫秒。"""
    output = await async_ping(ip, count=1, timeout=timeout, privileged=privileged)
    return output.avg_rtt if output.is_alive else None


async def tcping(ip: str, port: int, timeout: float = 1.0) -> float | None:
    """TCP 建连测速，返回毫秒。"""
    started = perf_counter()
    try:
        with fail_after(timeout):
            stream = await connect_tcp(ip, port)
            await stream.aclose()
        return (perf_counter() - started) * 1000
    except OSError, TimeoutError:
        return None


async def _measure(ip: str, config: PingConfig) -> float:
    """并发运行 ICMP 与各端口 TCP 探测，取首个有效 RTT；全部失败返回 inf。"""
    probes: list[Callable[[], Awaitable[float | None]]] = []
    if config.ping:
        probes.append(
            lambda: ping(
                ip,
                timeout=config.timeout,
                privileged=config.privileged,
            )
        )
    probes.extend(
        lambda port=port: tcping(ip, port, config.timeout)
        for port in sorted(config.port or set())
    )
    first: float | None = None

    async def run(probe: Callable[[], Awaitable[float | None]]) -> None:
        nonlocal first
        try:
            rtt = await probe()
        except Exception as error:
            logger.debug("测速 {} 失败: {}: {}", ip, type(error).__name__, error)
            return
        # 只采纳首个有效结果；屏蔽取消而晚到的探测不能覆盖它。
        if rtt is not None and first is None:
            first = rtt
            tg.cancel_scope.cancel()

    async with create_task_group() as tg:
        for probe in probes:
            tg.start_soon(run, probe)
    return float("inf") if first is None else first


@cached(SPEEDTEST_CACHE.get, key=_speedtest_key, lock=SPEEDTEST_CACHE.lock)
async def speedtest(ip: str | IPv4Address | IPv6Address, config: PingConfig) -> float:
    """测速指定 IP；结果缓存和同键调用合并由 decorator 统一处理。"""
    # 缓存命中和同键等待者不占测速名额，只有实际执行探测时才限流。
    async with _MEASURE_LIMIT:
        return await _measure(str(ip), config)
