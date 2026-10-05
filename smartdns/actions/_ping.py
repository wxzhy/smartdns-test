from __future__ import annotations

from threading import Lock
from time import perf_counter
from typing import TYPE_CHECKING

from anyio import (
    connect_tcp,
    create_memory_object_stream,
    create_task_group,
    fail_after,
)
from icmplib import async_ping

from smartdns.utils.cache_async import cached
from smartdns.utils.concurrency import GlobalCapacityLimiter

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping
    from ipaddress import IPv4Address, IPv6Address

    from smartdns.models.action import PingConfig

SpeedtestKey = tuple[str, bool, bool, tuple[int, ...], float]


class _CacheHolder:
    cache: MutableMapping[SpeedtestKey, float] | None = None


_cache_lock = Lock()
_MEASURE_LIMIT = GlobalCapacityLimiter(128)


def set_cache(cache: MutableMapping[SpeedtestKey, float] | None) -> None:
    """绑定结果缓存；缓存中只保存跨线程安全的数值。"""
    _CacheHolder.cache = cache


def _get_cache() -> MutableMapping[SpeedtestKey, float] | None:
    return _CacheHolder.cache


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
    if not probes:
        return float("inf")

    send, receive = create_memory_object_stream[float | None](len(probes))
    # 首个有效结果：先取消并退出 task group，再在组外关流返回；
    # 组内关流会让未及取消的探测任务向已关闭的流发送而抛
    # ClosedResourceError，吞掉已取得的结果。
    result: float | None = None

    async def run(probe: Callable[[], Awaitable[float | None]]) -> None:
        try:
            await send.send(await probe())
        except Exception:
            await send.send(None)

    async with create_task_group() as tg:
        for probe in probes:
            tg.start_soon(run, probe)
        for _ in probes:
            received = await receive.receive()
            if received is not None:
                result = received
                tg.cancel_scope.cancel()
                break

    await send.aclose()
    await receive.aclose()
    return result if result is not None else float("inf")


@cached(_get_cache, key=_speedtest_key, lock=_cache_lock)
async def speedtest(ip: str | IPv4Address | IPv6Address, config: PingConfig) -> float:
    """测速指定 IP；结果缓存和同键调用合并由 decorator 统一处理。"""
    # 缓存命中和同键等待者不占测速名额，只有实际执行探测时才限流。
    async with _MEASURE_LIMIT:
        return await _measure(str(ip), config)
