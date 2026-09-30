"""SpeedcheckAction 测速并发限制与倍率排序回归测试。"""

from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
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


def _action(
    *,
    measure: bool = True,
    tag_multipliers: dict[str, float] | None = None,
    asn_multipliers: dict[int, float] | None = None,
    max_num: int = 1,
    threshold: float = 100.0,
) -> SpeedcheckAction:
    return SpeedcheckAction(
        SpeedcheckActionConfig(
            name="speed",
            type="speedcheck",
            ping_config={"ping": False, "port": [443] if measure else []},
            match_ip=ResponseIPMatcher(),
            tag_multipliers=tag_multipliers or {},
            asn_multipliers=asn_multipliers or {},
            max_num=max_num,
            threshold=threshold,
        )
    )


def _context() -> Context:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    return Context(worker_id=0, request=request)


def _response(index: int, rdtype: str = "A") -> Response:
    address = (
        IPv4Address(f"198.51.{index // 256}.{index % 256}")
        if rdtype == "A"
        else IPv6Address(f"2001:db8::{index:x}")
    )
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        f";QUESTION\nexample.com. IN {rdtype}\n;ANSWER\n"
        f"example.com. 300 IN {rdtype} {address}\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.from_text(rdtype),
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    response = Response.from_answer(answer, upstream=f"r{index}")
    assert response.ip_infos is not None
    for info in response.ip_infos:
        info.ip = address
        info.resolver = response.upstream
    return response


def _candidate_context(*responses: Response) -> Context:
    context = _context()
    context.response = responses[0]
    context.candidates = {response.upstream: response for response in responses}
    context.ip_infos = {
        info.ip: info for response in responses for info in response.ip_infos or []
    }
    return context


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


async def test_weighted_tcp_rtt_selects_best_without_changing_measurements(
    monkeypatch,
) -> None:
    """关闭 ICMP、保留 TCP 时仍测速；排序与重复执行都不污染原始 RTT。"""
    preferred = _response(1)
    other = _response(2)
    assert preferred.ip_infos is not None
    assert other.ip_infos is not None
    preferred.ip_infos[0].country = {"preferred"}
    rtts = {preferred.ip_infos[0].ip: 40.0, other.ip_infos[0].ip: 20.0}

    async def fake_speedtest(ip, config):
        return rtts[ip]

    monkeypatch.setattr(speedcheck, "speedtest", fake_speedtest)
    action = _action(tag_multipliers={"preferred": 0.25})
    context = _context()
    context.candidates = {"r1": preferred, "r2": other}
    for response in (preferred, other):
        await action.on_resolver(context, response)

    for _ in range(2):
        await action.on_response(context)
        assert context.response is not None
        assert context.response.upstream == "r1"
        assert context.response.ip_list == ["198.51.0.1"]
        assert preferred.ip_infos[0].rtt == 40.0
        assert other.ip_infos[0].rtt == 20.0

    await _action().on_response(context)
    assert context.response is not None
    assert context.response.upstream == "r2"


@pytest.mark.parametrize(
    ("tags", "tag_multipliers", "asn", "asn_multipliers", "winner"),
    [
        ({"preferred"}, {"preferred": 2.0}, 64500, {64500: 0.25}, "r2"),
        ({"preferred"}, {"preferred": 1.0}, 64500, {64500: 2.0}, "r1"),
        ({"other"}, {"preferred": 2.0}, 64500, {64500: 0.25}, "r1"),
        (None, {}, 64500, {64500: 0.25}, "r1"),
        (set(), {}, 64500, {64500: 0.25}, "r1"),
        ({"other"}, {"preferred": 0.25}, 64501, {64500: 2.0}, "r1"),
        (None, {"preferred": 0.25}, None, {64500: 2.0}, "r1"),
        ({"a", "b"}, {"a": 2.0, "b": 0.25}, None, {}, "r2"),
        ({"a", "b"}, {"b": 0.25, "a": 2.0}, None, {}, "r1"),
    ],
)
async def test_multiplier_priority_and_default(
    tags: set[str] | None,
    tag_multipliers: dict[str, float],
    asn: int | None,
    asn_multipliers: dict[int, float],
    winner: str,
) -> None:
    """标签优先于 ASN，未知标签/ASN 默认为 1，同分保留原候选顺序。"""
    first, second = _response(1), _response(2)
    assert first.ip_infos is not None
    first.ip_infos[0].country = tags
    first.ip_infos[0].asn = asn
    context = _candidate_context(first, second)

    await _action(
        measure=False,
        tag_multipliers=tag_multipliers,
        asn_multipliers=asn_multipliers,
    ).on_response(context)

    assert context.response is not None
    assert context.response.upstream == winner


@pytest.mark.parametrize("rdtype", ["A", "AAAA"])
async def test_no_probes_sorts_only_by_multiplier_and_keeps_record_order(
    monkeypatch, rdtype: str
) -> None:
    """无测速时跨标签排序、忽略 RTT 阈值，并按 max_num 截取有序结果。"""
    action = _action(
        measure=False,
        tag_multipliers={"slow": 2.0, "preferred": 0.5},
        asn_multipliers={64500: 0.25, 64501: 0.1, 64502: 3.0},
        max_num=3,
        threshold=0,
    )
    responses = [_response(index, rdtype) for index in range(1, 5)]
    tags = [{"slow"}, {"unconfigured"}, None, {"preferred"}]
    asns = [64501, 64500, 64503, 64502]
    for response, labels, asn in zip(responses, tags, asns, strict=True):
        assert response.ip_infos is not None
        response.ip_infos[0].country = labels
        response.ip_infos[0].asn = asn
    probes = []

    async def fake_speedtest(ip, config):
        probes.append(ip)
        return 1.0

    monkeypatch.setattr(speedcheck, "speedtest", fake_speedtest)
    context = _context()
    context.candidates = {response.upstream: response for response in responses}
    for response in responses:
        await action.on_resolver(context, response)
    await action.on_response(context)

    expected = [
        str(info.ip) for index in (1, 3, 2) for info in responses[index].ip_infos or []
    ]
    assert probes == []
    assert context.response is not None
    assert context.response.upstream == "r2"
    assert context.response.ip_list == expected
    assert context.response.ans is not None
    assert context.response.ans.rrset is not None
    assert [rr.address for rr in context.response.ans.rrset] == expected
    assert responses[1].ip_infos is not None
    assert responses[1].ip_infos[0].rtt is None


async def test_weighted_threshold_applies_to_asn_multipliers() -> None:
    responses = [_response(index) for index in range(1, 4)]
    for response, rtt, asn in zip(
        responses, [40.0, 25.0, 48.0], [64500, 64501, 64500], strict=True
    ):
        assert response.ip_infos is not None
        response.ip_infos[0].rtt = rtt
        response.ip_infos[0].asn = asn
    context = _candidate_context(*responses)

    await _action(
        asn_multipliers={64500: 0.5, 64501: 2.0}, max_num=3, threshold=5.0
    ).on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["198.51.0.1", "198.51.0.3"]
    assert context.response is not responses[0]
    assert responses[0].ip_list == ["198.51.0.1"]


async def test_default_multipliers_keep_existing_rtt_and_tag_selection() -> None:
    responses = [_response(index) for index in range(1, 5)]
    for response, rtt, tags in zip(
        responses,
        [20.0, 24.0, 21.0, 30.0],
        [{"cn"}, {"cn"}, {"other"}, {"cn"}],
        strict=True,
    ):
        assert response.ip_infos is not None
        response.ip_infos[0].rtt = rtt
        response.ip_infos[0].country = tags
    context = _candidate_context(*responses)

    await _action(max_num=3, threshold=5.0).on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["198.51.0.1", "198.51.0.2"]


async def test_no_probes_default_multipliers_keep_candidate_order() -> None:
    responses = [_response(index) for index in (3, 1, 2)]
    context = _candidate_context(*responses)

    await _action(measure=False, max_num=2).on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["198.51.0.3", "198.51.0.1"]


@pytest.mark.parametrize("measure", [True, False])
@pytest.mark.parametrize("rtt", [None, float("inf"), float("nan")])
async def test_valid_rtt_takes_priority_over_lower_multiplier(
    rtt: float | None, measure: bool
) -> None:
    first, second = _response(1), _response(2)
    assert first.ip_infos is not None
    assert second.ip_infos is not None
    first.ip_infos[0].rtt = rtt
    first.ip_infos[0].asn = 64500
    second.ip_infos[0].rtt = 20.0
    context = _candidate_context(first, second)

    await _action(measure=measure, asn_multipliers={64500: 0.01}).on_response(context)

    assert context.response is not None
    assert context.response.upstream == "r2"


@pytest.mark.parametrize("measure", [True, False])
@pytest.mark.parametrize("rdtype", ["A", "AAAA"])
async def test_no_valid_rtt_sorts_by_multiplier(measure: bool, rdtype: str) -> None:
    """缺失、失败及 NaN 均不算有效 RTT，全部不可用时按倍率跨标签排序。"""
    responses = [_response(index, rdtype) for index in range(1, 5)]
    for response, rtt, labels, asn in zip(
        responses,
        [float("inf"), None, float("nan"), float("inf")],
        [{"slow"}, {"unconfigured"}, None, {"preferred"}],
        [64501, 64500, 64503, 64502],
        strict=True,
    ):
        assert response.ip_infos is not None
        response.ip_infos[0].rtt = rtt
        response.ip_infos[0].country = labels
        response.ip_infos[0].asn = asn
    context = _candidate_context(*responses)

    await _action(
        measure=measure,
        tag_multipliers={"slow": 2.0, "preferred": 0.5},
        asn_multipliers={64500: 0.25, 64501: 0.1, 64502: 3.0},
        max_num=3,
        threshold=0,
    ).on_response(context)

    expected = [
        str(info.ip) for index in (1, 3, 2) for info in responses[index].ip_infos or []
    ]
    assert context.response is not None
    assert context.response.upstream == "r2"
    assert context.response.ip_list == expected
    assert context.response is not responses[1]


async def test_disabled_probes_use_existing_rtt_and_weighted_order() -> None:
    """关闭探测只阻止新测速；已有的 RTT 仍优先于单纯倍率。"""
    responses = [_response(index) for index in range(1, 4)]
    for response, rtt, asn in zip(
        responses, [40.0, None, 20.0], [64500, 64501, 64502], strict=True
    ):
        assert response.ip_infos is not None
        response.ip_infos[0].rtt = rtt
        response.ip_infos[0].asn = asn
    context = _candidate_context(*responses)

    await _action(
        measure=False,
        asn_multipliers={64500: 0.25, 64501: 0.01, 64502: 1.0},
        max_num=2,
    ).on_response(context)

    assert context.response is not None
    assert context.response.upstream == "r1"
    assert context.response.ip_list == ["198.51.0.1", "198.51.0.3"]


async def test_zero_rtt_is_valid_and_takes_priority() -> None:
    first, second = _response(1), _response(2)
    assert first.ip_infos is not None
    first.ip_infos[0].rtt = 0.0
    first.ip_infos[0].asn = 64500
    context = _candidate_context(second, first)

    await _action(measure=False, asn_multipliers={64500: 2.0}).on_response(context)

    assert context.response is not None
    assert context.response.upstream == "r1"


async def test_all_failed_probes_use_multiplier_order(monkeypatch) -> None:
    """真实采样流程全部失败后，仍按倍率选择应答，失败 RTT 不被改写。"""
    first, second = _response(1), _response(2)
    assert first.ip_infos is not None
    assert second.ip_infos is not None
    first.ip_infos[0].country = {"slow"}
    second.ip_infos[0].country = {"preferred"}
    action = _action(tag_multipliers={"slow": 2.0, "preferred": 0.5})

    async def failing_speedtest(ip, config):
        raise RuntimeError("probe failed")

    monkeypatch.setattr(speedcheck, "speedtest", failing_speedtest)
    context = _context()
    context.response = first
    context.candidates = {"r1": first, "r2": second}
    for response in (first, second):
        await action.on_resolver(context, response)
    await action.on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["198.51.0.2"]
    assert first.ip_infos[0].rtt == float("inf")
    assert second.ip_infos[0].rtt == float("inf")
