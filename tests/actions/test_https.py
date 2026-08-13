"""Phase 7：HTTPSAction 多记录处理与 copy-on-write 回归测试。

修复前：循环内 `return` 导致多条 HTTPS 记录只处理第一条；且就地改 rr.params._odict
污染可能被缓存/共享的不可变 rdata。修复后：所有记录都处理，且原 rdata 不被改写。
"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from dns.resolver import Answer

from smartdns.actions.https import HTTPSAction
from smartdns.models.action import HTTPSActionConfig
from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher

if TYPE_CHECKING:
    from dns.message import QueryMessage
    from dns.rrset import RRset

    from smartdns.nameservers.client import HTTPClient


def _https_response(*records: str) -> Response:
    text = (
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN HTTPS\n;ANSWER\n"
        + "".join(f"example.com. 300 IN HTTPS {r}\n" for r in records)
    )
    msg = dns.message.from_text(text)
    answer = Answer(
        from_text("example.com."),
        RdataType.HTTPS,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _rrset(response: Response | None) -> RRset:
    assert response is not None
    assert response.ans is not None
    assert response.ans.rrset is not None
    return response.ans.rrset


def _https_request() -> Request:
    return Request.from_message(dns.message.make_query("example.com.", "HTTPS"), "test")


def _action(
    add_ech: bool = True, remove_hint: bool = True, remove_h3: bool = True
) -> HTTPSAction:
    config = HTTPSActionConfig(
        name="h",
        type="https",
        match_name=RequestMatcher(),
        match_ip=ResponseIPMatcher(),
        add_ech=add_ech,
        remove_hint=remove_hint,
        remove_h3=remove_h3,
    )
    return HTTPSAction(config, cast("HTTPClient", None))


async def test_all_https_records_processed() -> None:
    # 两条 HTTPS 记录都应被移除 hint/h3（修复前只处理第一条）。
    action = _action(add_ech=False)
    response = _https_response(
        "1 . alpn=h2,h3 ipv4hint=1.2.3.4", "2 . alpn=h3 ipv6hint=2001:db8::1"
    )
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    for rr in _rrset(context.response):
        assert ParamKey.IPV4HINT not in rr.params
        assert ParamKey.IPV6HINT not in rr.params
        if ParamKey.ALPN in rr.params:
            assert b"h3" not in rr.params[ParamKey.ALPN].ids


async def test_copy_on_write_does_not_mutate_original() -> None:
    action = _action(add_ech=False)
    response = _https_response("1 . alpn=h2,h3 ipv4hint=1.2.3.4")
    original_rr = next(iter(_rrset(response)))
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    # 原 rdata 未被改写：仍保留 ipv4hint 与 h3。
    assert ParamKey.IPV4HINT in original_rr.params
    assert b"h3" in original_rr.params[ParamKey.ALPN].ids


async def test_h3_only_alpn_is_removed_entirely() -> None:
    action = _action(add_ech=False, remove_hint=False)
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ALPN not in rr.params
