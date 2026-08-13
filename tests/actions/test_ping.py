"""测速单位、缓存键和同键 in-flight 合并回归测试。"""

from asyncio import create_task
from typing import TYPE_CHECKING

import pytest
from anyio import Event
from anyio.lowlevel import checkpoint

from smartdns.actions import _ping
from smartdns.models.action import PingConfig

if TYPE_CHECKING:
    from collections.abc import MutableMapping


@pytest.fixture(autouse=True)
def _reset_speed_cache() -> None:
    _ping.set_cache(None)


async def test_tcping_returns_milliseconds(monkeypatch) -> None:
    class _Stream:
        async def aclose(self) -> None:
            return None

    values = iter((10.0, 10.025))
    monkeypatch.setattr(_ping, "perf_counter", lambda: next(values))

    async def connect_tcp(ip: str, port: int) -> _Stream:
        return _Stream()

    monkeypatch.setattr(_ping, "connect_tcp", connect_tcp)
    result = await _ping.tcping("192.0.2.1", 443, timeout=1)
    assert result == pytest.approx(25.0)


async def test_speedtest_cache_key_includes_method_ports_and_timeout(
    monkeypatch,
) -> None:
    calls: list[tuple[bool, tuple[int, ...], float]] = []

    async def measure(ip: str, config: PingConfig) -> float:
        key = (config.ping, tuple(sorted(config.port or set())), config.timeout)
        calls.append(key)
        return float(len(calls))

    monkeypatch.setattr(_ping, "_measure", measure)
    cache: MutableMapping[_ping.SpeedtestKey, float] = {}
    _ping.set_cache(cache)
    configs = [
        PingConfig(ping=True, port={443}, timeout=0.3),
        PingConfig(ping=False, port={443}, timeout=0.3),
        PingConfig(ping=True, port={80}, timeout=0.3),
        PingConfig(ping=True, port={443}, timeout=0.5),
    ]

    first = await _ping.speedtest("192.0.2.1", configs[0])
    assert await _ping.speedtest("192.0.2.1", configs[0]) == first
    for config in configs[1:]:
        await _ping.speedtest("192.0.2.1", config)

    assert len(calls) == len(configs)
    assert len(cache) == len(configs)


async def test_speedtest_deduplicates_same_key_but_not_different_config(
    monkeypatch,
) -> None:
    started = Event()
    release = Event()
    calls: list[tuple[int, ...]] = []

    async def measure(ip: str, config: PingConfig) -> float:
        calls.append(tuple(sorted(config.port or set())))
        if len(calls) == 2:
            started.set()
        await release.wait()
        return float(next(iter(config.port or {0})))

    monkeypatch.setattr(_ping, "_measure", measure)
    same = PingConfig(ping=False, port={443}, timeout=0.3)
    different = PingConfig(ping=False, port={80}, timeout=0.3)

    first = create_task(_ping.speedtest("192.0.2.1", same))
    duplicate = create_task(_ping.speedtest("192.0.2.1", same))
    other = create_task(_ping.speedtest("192.0.2.1", different))
    await started.wait()
    await checkpoint()
    assert sorted(calls) == [(80,), (443,)]
    release.set()

    assert await first == 443.0
    assert await duplicate == 443.0
    assert await other == 80.0
