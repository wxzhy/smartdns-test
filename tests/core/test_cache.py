"""Master 应答缓存行为回归测试：cached() 装饰 + TLRUCache 持久层。"""

from inspect import signature
from ipaddress import IPv4Address
from time import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.message
from anyio import sleep
from dns.edns import ECSOption
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions._helper import replace_response_ip
from smartdns.core.master import Master, _cache_key
from smartdns.models.context import Request, Response

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.models.config import Config


def _answer(qname: str = "example.com.", ttl: int = 300) -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        f";QUESTION\n{qname} IN A\n;ANSWER\n"
        f"{qname} {ttl} IN A 203.0.113.1\n"
    )
    return Answer(
        from_text(qname),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _nxdomain_answer() -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        ";QUESTION\nexample.com. IN A\n;AUTHORITY\n"
        "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 60\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _request(
    client: str,
    qname: str = "example.com.",
    listener: str = "udp",
    ecs: str | None = None,
) -> Request:
    if ecs is None:
        message = dns.message.make_query(qname, "A")
    else:
        message = dns.message.make_query(
            qname, "A", use_edns=0, options=[ECSOption(ecs, 24)]
        )
    return Request.from_message(message, listener, IPv4Address(client))


class _FakeMaster(Master):
    """不启动真实 Worker/portal 的最小 Master 桩；_query_worker 按序产出预置响应。"""

    def __init__(self, responses: list[Response], cache_size: int = 10) -> None:
        config = SimpleNamespace(worker_count=1, cache_size=cache_size)
        super().__init__(cast("Config", config))
        self._responses = list(responses)
        self.calls = 0

    async def _query_worker(self, request: Request) -> Response:
        self.calls += 1
        return self._responses[min(self.calls - 1, len(self._responses) - 1)]


async def test_second_query_hits_cache_without_worker() -> None:
    master = _FakeMaster([Response.from_answer(_answer(), upstream="upstream")])
    first = await master.dispatch(_request("192.0.2.1"))
    second = await master.dispatch(_request("192.0.2.2"))

    assert master.calls == 1
    assert first is not None
    assert second is not None
    assert second.rcode() == Rcode.NOERROR


async def test_replaced_a_cannot_outlive_cname_chain_in_master_cache() -> None:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 1 IN CNAME edge.example.com.\n"
        "edge.example.com. 300 IN A 192.0.2.1\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    response = replace_response_ip(
        Response.from_answer(answer, upstream="up"), {IPv4Address("203.0.113.1")}, 300
    )
    assert response.ans is not None
    assert response.ans.rrset is not None
    assert response.ans.rrset.ttl == 300
    assert 0 < response.ans.expiration - time() <= 1
    master = _FakeMaster([response])
    await master.dispatch(_request("192.0.2.10"))
    await sleep(1.03)
    await master.dispatch(_request("192.0.2.11"))
    assert master.calls == 2


async def test_rewrite_does_not_restart_remaining_cname_ttl() -> None:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 1 IN CNAME edge.example.com.\n"
        "edge.example.com. 300 IN A 192.0.2.1\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    response = Response.from_answer(answer, upstream="up")
    await sleep(0.03)
    for ttl in (None, 300):
        changed = replace_response_ip(response, {IPv4Address("203.0.113.1")}, ttl)
        assert changed.ans is not None
        assert changed.ans.expiration <= answer.expiration


async def test_cache_hit_decays_ttl_by_remaining_lifetime() -> None:
    answer = _answer()
    answer.expiration = time() + 3.5  # 压缩 TTL 使衰减可观察
    master = _FakeMaster([Response.from_answer(answer, upstream="upstream")])
    first = await master.dispatch(_request("192.0.2.1"))
    await sleep(1)
    second = await master.dispatch(_request("192.0.2.2"))

    assert master.calls == 1
    assert first is not None
    assert second is not None
    first_ttl = first.answer[0].ttl
    second_ttl = second.answer[0].ttl
    # 剩余生存期向零取整；3.5s 条目经 1s 流逝后 TTL 应回落约 1。
    assert 2 <= first_ttl <= 3
    assert 1 <= second_ttl <= 2
    assert second_ttl <= first_ttl


async def test_cache_hit_returns_copy_not_shared_object() -> None:
    master = _FakeMaster([Response.from_answer(_answer(), upstream="upstream")])
    first = await master.dispatch(_request("192.0.2.1"))
    assert first is not None
    first.answer[0].clear()  # 改写返回给调用方的副本中的 RRset

    second = await master.dispatch(_request("192.0.2.2"))
    assert second is not None
    assert len(second.answer[0]) == 1  # 缓存内原件不受影响
    assert master.calls == 1


async def test_negative_answer_cached_with_soa() -> None:
    master = _FakeMaster(
        [Response.from_answer(_nxdomain_answer(), upstream="upstream")]
    )
    first = await master.dispatch(_request("192.0.2.1"))
    second = await master.dispatch(_request("192.0.2.2"))

    assert master.calls == 1
    assert first is not None
    assert second is not None
    assert second.rcode() == Rcode.NXDOMAIN
    authority = list(second.authority)
    assert authority
    assert authority[0].rdtype == RdataType.SOA


async def test_cache_entry_expires_and_requeries() -> None:
    answer = _answer()
    answer.expiration = time() + 0.05
    master = _FakeMaster(
        [
            Response.from_answer(answer, upstream="upstream"),
            Response.from_answer(_answer(), upstream="upstream"),
        ]
    )
    await master.dispatch(_request("192.0.2.1"))
    await sleep(0.15)
    second = await master.dispatch(_request("192.0.2.2"))

    assert master.calls == 2
    assert second is not None
    assert second.rcode() == Rcode.NOERROR


async def test_servfail_not_cached() -> None:
    master = _FakeMaster([Response.from_rcode(Rcode.SERVFAIL, upstream="")])
    first = await master.dispatch(_request("192.0.2.1"))
    second = await master.dispatch(_request("192.0.2.2"))

    assert master.calls == 2
    assert first is not None
    assert second is not None
    assert first.rcode() == Rcode.SERVFAIL
    assert second.rcode() == Rcode.SERVFAIL


async def test_cache_isolates_listeners_and_ecs() -> None:
    responses = [Response.from_answer(_answer(), upstream="upstream") for _ in range(3)]
    master = _FakeMaster(responses)
    await master.dispatch(_request("192.0.2.1", listener="udp"))
    assert master.calls == 1
    await master.dispatch(_request("192.0.2.1", listener="tcp"))
    assert master.calls == 2
    await master.dispatch(_request("192.0.2.1", ecs="198.51.100.0"))
    assert master.calls == 3
    # 客户端地址不入键：同键查询共享条目。
    await master.dispatch(_request("192.0.2.99", listener="udp"))
    assert master.calls == 3


def test_cache_key_annotation_is_reflectable_at_runtime() -> None:
    """Python 3.14 下反射缓存键函数不应因 TYPE_CHECKING 注解而失败。"""
    params = signature(_cache_key).parameters
    assert list(params) == ["request"]
    assert str(signature(_cache_key).return_annotation) == "CacheKey"
