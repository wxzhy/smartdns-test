from __future__ import annotations

from asyncio import create_task, get_running_loop, shield
from contextlib import suppress
from threading import Lock
from time import perf_counter
from typing import TYPE_CHECKING, Any

from anyio import (
    connect_tcp,
    create_memory_object_stream,
    create_task_group,
    fail_after,
)
from icmplib import async_ping

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping
    from ipaddress import IPv4Address, IPv6Address

    from smartdns.models.action import PingConfig

SpeedtestKey = tuple[str, bool, tuple[int, ...], float]


class _CacheHolder:
    cache: MutableMapping[SpeedtestKey, float] | None = None


_inflight: dict[tuple[int, SpeedtestKey], Any] = {}
_cache_lock = Lock()
_inflight_lock = Lock()


def set_cache(cache: MutableMapping[SpeedtestKey, float] | None) -> None:
    """绑定结果缓存；缓存中只保存跨线程安全的数值。"""
    _CacheHolder.cache = cache


async def ping(ip: str, timeout: float = 1.0) -> float | None:
    """ICMP 测速，返回毫秒。"""
    output = await async_ping(ip, count=1, timeout=timeout, privileged=False)
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
        probes.append(lambda: ping(ip, config.timeout))
    probes.extend(
        lambda port=port: tcping(ip, port, config.timeout)
        for port in sorted(config.port or set())
    )
    if not probes:
        return float("inf")

    send, receive = create_memory_object_stream[float | None](len(probes))

    async def run(probe: Callable[[], Awaitable[float | None]]) -> None:
        try:
            await send.send(await probe())
        except Exception:
            await send.send(None)

    async with create_task_group() as tg:
        for probe in probes:
            tg.start_soon(run, probe)
        for _ in probes:
            result = await receive.receive()
            if result is not None:
                tg.cancel_scope.cancel()
                await send.aclose()
                await receive.aclose()
                return result
    await send.aclose()
    await receive.aclose()
    return float("inf")


async def speedtest(ip: str | IPv4Address | IPv6Address, config: PingConfig) -> float:
    """缓存并合并当前事件循环内的同配置测速。"""
    key: SpeedtestKey = (
        str(ip),
        config.ping,
        tuple(sorted(config.port or set())),
        config.timeout,
    )
    cache = _CacheHolder.cache
    if cache is not None:
        with _cache_lock, suppress(KeyError):
            return cache[key]

    loop = get_running_loop()
    loop_key = (id(loop), key)
    with _inflight_lock:
        task = _inflight.get(loop_key)
        if task is None:
            task = create_task(_measure(str(ip), config))
            _inflight[loop_key] = task
    try:
        result = await shield(task)
        cache = _CacheHolder.cache
        if cache is not None:
            with _cache_lock:
                cache[key] = result
        return result
    finally:
        if task.done():
            with _inflight_lock:
                _inflight.pop(loop_key, None)
