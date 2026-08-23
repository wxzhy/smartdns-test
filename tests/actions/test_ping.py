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


@pytest.mark.parametrize("privileged", [False, True])
async def test_ping_forwards_privileged_mode(monkeypatch, privileged: bool) -> None:
    calls: list[tuple[str, int, float, bool]] = []

    class _Host:
        is_alive = True
        avg_rtt = 12.5

    async def async_ping(
        ip: str, *, count: int, timeout: float, privileged: bool
    ) -> _Host:
        calls.append((ip, count, timeout, privileged))
        return _Host()

    monkeypatch.setattr(_ping, "async_ping", async_ping)

    assert await _ping.ping("192.0.2.1", timeout=0.5, privileged=privileged) == 12.5
    assert calls == [("192.0.2.1", 1, 0.5, privileged)]


async def test_measure_uses_configured_ping_privilege(monkeypatch) -> None:
    calls: list[tuple[str, float, bool]] = []

    async def ping(ip: str, timeout: float, privileged: bool) -> float:
        calls.append((ip, timeout, privileged))
        return 5.0

    monkeypatch.setattr(_ping, "ping", ping)

    config = PingConfig(ping=True, privileged=True, timeout=0.4)
    assert await _ping._measure("192.0.2.1", config) == 5.0
    assert calls == [("192.0.2.1", 0.4, True)]


async def test_speedtest_cache_key_includes_all_probe_options(
    monkeypatch,
) -> None:
    calls: list[tuple[bool, bool, tuple[int, ...], float]] = []

    async def measure(ip: str, config: PingConfig) -> float:
        key = (
            config.ping,
            config.privileged,
            tuple(sorted(config.port or set())),
            config.timeout,
        )
        calls.append(key)
        return float(len(calls))

    monkeypatch.setattr(_ping, "_measure", measure)
    cache: MutableMapping[_ping.SpeedtestKey, float] = {}
    _ping.set_cache(cache)
    configs = [
        PingConfig(ping=True, privileged=False, port={443}, timeout=0.3),
        PingConfig(ping=False, port={443}, timeout=0.3),
        PingConfig(ping=True, port={80}, timeout=0.3),
        PingConfig(ping=True, port={443}, timeout=0.5),
        PingConfig(ping=True, privileged=True, port={443}, timeout=0.3),
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
