"""SpeedcheckAction 并发限制回归测试。"""

from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast

import dns.message
from anyio import Event, create_task_group, fail_after
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions import speedcheck
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.models.action import SpeedcheckActionConfig
from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import ResponseIPMatcher

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _action() -> SpeedcheckAction:
    return SpeedcheckAction(
        SpeedcheckActionConfig(
            name="speed",
            type="speedcheck",
            ping_config={"ping": False, "port": [443]},
            match_ip=ResponseIPMatcher(),
        )
    )


def _context() -> Context:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    return Context(worker_id=0, request=request)


def _response(index: int) -> Response:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        f"example.com. 300 IN A 198.51.{index // 256}.{index % 256}\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    response = Response.from_answer(answer, upstream=f"r{index}")
    assert response.ip_infos is not None
    for info in response.ip_infos:
        info.ip = IPv4Address(f"198.51.{index // 256}.{index % 256}")
    return response


async def test_speedcheck_measure_limit_is_128(monkeypatch) -> None:
    """多个 Worker 任务共享线程信号量，活动测速数不超过 128。"""
    monkeypatch.setattr(speedcheck, "match_response", lambda matcher, response: True)
    active = 0
    maximum = 0
    started = Event()
    release = Event()

    async def fake_speedtest(ip, config):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        if active == 128:
            started.set()
        await release.wait()
        active -= 1
        return 1.0

    monkeypatch.setattr(speedcheck, "speedtest", fake_speedtest)
    action = _action()

    async with create_task_group() as tg:
        for index in range(129):
            tg.start_soon(action.on_resolver, _context(), _response(index + 1))
        with fail_after(5):
            await started.wait()
        assert maximum == 128
        assert active == 128
        release.set()


async def test_speedcheck_measure_limit_is_released_on_failure(monkeypatch) -> None:
    """测速抛错后仍释放许可，后续任务不会永久等待。"""
    monkeypatch.setattr(speedcheck, "match_response", lambda matcher, response: True)
    calls = 0

    async def failing_speedtest(ip, config):
        nonlocal calls
        calls += 1
        raise RuntimeError("probe failed")

    monkeypatch.setattr(speedcheck, "speedtest", failing_speedtest)
    action = _action()
    await action.on_resolver(_context(), _response(1))
    await action.on_resolver(_context(), _response(2))
    assert calls == 2
