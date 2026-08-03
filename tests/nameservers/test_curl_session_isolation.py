"""Phase 2 回归测试：每个 CurlNameserver 必须独占一个 HTTP 会话。

修复前所有 CurlNameserver 共享 HTTPClient 的单一 AsyncSession，并逐请求修改其
curl_options[ECH]，在并发下产生竞态与跨上游 ECH 泄漏。修复后各上游经
create_session() 独立持有会话。
"""

from typing import cast

from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.curl import CurlNameserver


class _FakeClient:
    """最小 HTTPClient 替身：每次 create_session 返回一个唯一、可区分的对象。"""

    def __init__(self) -> None:
        self.sessions: list[object] = []

    def create_session(self, extra_options=None) -> object:
        session = object()
        self.sessions.append(session)
        return session


def _make_config(name: str, url: str, ech: str) -> CurlNameserverConfig:
    return CurlNameserverConfig(name=name, type="curl", url=url, ech=ech)


async def test_each_curl_nameserver_owns_a_distinct_session() -> None:
    client = _FakeClient()
    ns1 = CurlNameserver(
        _make_config("a", "https://a.example/dns-query", "a.example"),
        cast(HTTPClient, client),
    )
    ns2 = CurlNameserver(
        _make_config("b", "https://b.example/dns-query", "b.example"),
        cast(HTTPClient, client),
    )

    await ns1.start()
    await ns2.start()

    assert ns1._curl is not None
    assert ns2._curl is not None
    # 两个上游必须持有各自独立的会话对象。
    assert ns1._curl is not ns2._curl
    assert len(client.sessions) == 2
