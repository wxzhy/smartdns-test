"""Phase 6：Router 黑洞与域名 fail-closed 回归测试。

修复前：匹配的路由若无 resolver（或 resolver 未产出应答），query 因 `not context.response`
返回 True，声称"已处理"却无应答 → worker 得到 None → SERVFAIL（黑洞）。
修复后：无应答时返回 False，交后续路由处理。
另：domain_include 已配但无 geo 数据（country=None）时应 fail-closed 不匹配。
"""

from typing import cast

import dns.message

from smartdns.actions.manager import ActionManager
from smartdns.models.context import Context, Request
from smartdns.models.rule import Matcher, Rule
from smartdns.resolvers.manager import ResolverManager
from smartdns.routing.router import Router


class _FakeManager:
    def get(self, name: str) -> None:
        return None


def _router(rule: Rule) -> Router:
    fake = _FakeManager()
    return Router(rule, cast(ResolverManager, fake), cast(ActionManager, fake))


def _context(qname: str = "example.com.", qtype: str = "A") -> Context:
    msg = dns.message.make_query(qname, qtype)
    request = Request.from_message(msg, "test")
    return Context(worker_id=0, request=request)


async def test_no_resolver_falls_through_instead_of_blackhole() -> None:
    # 无 matcher（匹配所有）、无 resolver：不吞请求，返回 False 交后续路由。
    router = _router(Rule(name="t"))
    context = _context()
    assert await router.query(context) is False
    assert context.response is None


def test_domain_include_fail_closed_without_geodata() -> None:
    # domain_include 已配但无 geo 数据（country=None）：fail-closed 不匹配。
    router = _router(Rule(name="t", matcher=Matcher(domain_include={"cn"})))
    context = _context()
    context.request.name_info.country = None
    assert router.match(context) is False


def test_domain_include_matches_when_tag_present() -> None:
    router = _router(Rule(name="t", matcher=Matcher(domain_include={"cn"})))
    context = _context()
    context.request.name_info.country = {"cn"}
    assert router.match(context) is True
