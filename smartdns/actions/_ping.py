from asyncio import as_completed
from ipaddress import IPv4Address, IPv6Address
from threading import Lock
from time import time

from anyio import connect_tcp, create_task_group, fail_after
from icmplib import async_ping
from loguru import logger
from pydantic.networks import IPvAnyAddress

from smartdns.models.action import PingConfig
from smartdns.utils.cache_async import cached

cache = None


def set_cache(cache_instance):
    global cache
    cache = cache_instance


async def ping(ip: str | IPvAnyAddress, timeout: float = 1.0) -> float | None:
    """Ping 指定 IP 地址，返回延迟（毫秒），失败返回 None。"""
    if not isinstance(ip, str):
        ip = str(ip)
    output = await async_ping(ip, count=1, timeout=timeout, privileged=False)
    if not output.is_alive:
        return None
    return output.avg_rtt


async def tcping(
    ip: str | IPv4Address | IPv6Address, port: int, timeout: float = 1.0
) -> float | None:
    """TCP Ping 指定 IP 地址和端口，返回延迟（毫秒），失败返回 None。"""
    start_time = time()
    try:
        with fail_after(timeout):
            async with await connect_tcp(ip, port) as conn:
                return time() - start_time
    except Exception:
        return None


@cached(key=lambda ip, config: ip, cache=cache, lock=Lock())
async def speedtest(
    ip: str | IPv4Address | IPv6Address, config: PingConfig
) -> float | None:
    """测速指定 IP 地址和端口，返回延迟（毫秒），失败返回 None。"""
    async with create_task_group() as tg:
        handles = []
        logger.debug(f"开始测速: {ip}，配置: {config}")
        if config.ping:
            handles.append(tg.start_soon(ping, ip, config.timeout))
        if config.port is not None:
            # 并发测试
            handles.extend(
                [
                    tg.start_soon(tcping, ip, port, config.timeout)
                    for port in config.port
                ]
            )
        for handle in as_completed(handles):
            result = await handle
            logger.debug(f"测速结果: {ip} -> {result}，配置: {config}")
            if result is not None:
                tg.cancel()
                return result
    return None
