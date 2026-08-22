"""FilterAction 候选标记、CNAME 链匹配与配置隔离测试。"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions.filter import FilterAction
from smartdns.models.action import FilterActionConfig, FilterItem
from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _config(
    match_name: RequestMatcher, match_ip: ResponseIPMatcher
) -> FilterActionConfig:
    return FilterActionConfig(
        name="f",
        type="filter",
        filters=[FilterItem(match_name=match_name, match_ip=match_ip)],
    )


def _request(rdtype: str = "A") -> Request:
    return Request.from_message(dns.message.make_query("example.com.", rdtype), "test")


def _response(rdtype: str, answer_text: str, qname: str = "example.com.") -> Response:
    msg = dns.message.from_text(answer_text)
    answer = Answer(
        from_text(qname),
        RdataType.from_text(rdtype),
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _a_response(ip: str = "192.0.2.1") -> Response:
    return _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        f"example.com. 300 IN A {ip}\n",
    )


def _cname_response() -> Response:
    return _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nwww.example.com. IN A\n;ANSWER\n"
        "www.example.com. 300 IN CNAME web.example.net.\n"
        "web.example.net. 300 IN A 192.0.2.1\n",
        qname="www.example.com.",
    )


def _mx_response() -> Response:
    return _response(
        "MX",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN MX\n;ANSWER\n"
        "example.com. 300 IN MX 10 mail.example.com.\n",
    )


async def test_ip_exclude_marks_candidate_invalid() -> None:
    action = FilterAction(
        _config(RequestMatcher(), ResponseIPMatcher(ip_exclude={"twitter"}))
    )
    response = _a_response()
    assert response.ip_infos is not None
    response.ip_infos[0].country = {"twitter"}
    context = Context(worker_id=0, request=_request())
    await action.on_resolver(context, response)
    assert response.invalid is True
    assert context.response is None  # 临时挂载已恢复


async def test_domain_exclude_skips_filtering() -> None:
    action = FilterAction(
        _config(
            RequestMatcher(domain_exclude={"cn"}),
            ResponseIPMatcher(ip_exclude={"twitter"}),
        )
    )
    request = _request()
    request.name_info.country = {"cn"}
    response = _a_response()
    assert response.ip_infos is not None
    response.ip_infos[0].country = {"twitter"}
    context = Context(worker_id=0, request=request)
    await action.on_resolver(context, response)
    assert response.invalid is False


async def test_cname_chain_participates_in_matching() -> None:
    # 请求域名无标签、CNAME 链带 facebook：exclude 应命中并跳过该条过滤，
    # 即使响应 IP 命中 ip_exclude 也不标记 invalid。
    action = FilterAction(
        _config(
            RequestMatcher(domain_exclude={"facebook"}),
            ResponseIPMatcher(ip_exclude={"twitter"}),
        )
    )
    response = _cname_response()
    assert response.name_infos is not None
    assert response.ip_infos is not None
    response.name_infos[0].country = {"facebook"}
    response.ip_infos[0].country = {"twitter"}
    context = Context(worker_id=0, request=_request())
    await action.on_resolver(context, response)
    assert response.invalid is False


async def test_cname_chain_without_exclude_marks_invalid() -> None:
    # CNAME 链不带排除标签时正常进入 IP 过滤。
    action = FilterAction(
        _config(
            RequestMatcher(domain_exclude={"facebook"}),
            ResponseIPMatcher(ip_exclude={"twitter"}),
        )
    )
    response = _cname_response()
    assert response.ip_infos is not None
    response.ip_infos[0].country = {"twitter"}
    context = Context(worker_id=0, request=_request())
    await action.on_resolver(context, response)
    assert response.invalid is True


async def test_unsupported_query_type_is_skipped() -> None:
    action = FilterAction(
        _config(RequestMatcher(), ResponseIPMatcher(ip_exclude={"twitter"}))
    )
    context = Context(worker_id=0, request=_request("MX"))
    await action.on_resolver(context, _mx_response())
    assert context.response is None


async def test_context_response_restored_after_mount() -> None:
    action = FilterAction(
        _config(RequestMatcher(), ResponseIPMatcher(ip_exclude={"twitter"}))
    )
    prior = _a_response("192.0.2.2")
    response = _a_response()
    assert response.ip_infos is not None
    response.ip_infos[0].country = {"twitter"}
    context = Context(worker_id=0, request=_request(), response=prior)
    await action.on_resolver(context, response)
    assert context.response is prior
    assert response.invalid is True


def test_config_filters_not_mutated() -> None:
    config = _config(RequestMatcher(), ResponseIPMatcher(ip_exclude={"twitter"}))
    action = FilterAction(config)
    assert config.filters[0].match_name.query_types is None
    assert action.map[0].match_name.query_types == {"A", "AAAA", "HTTPS"}
