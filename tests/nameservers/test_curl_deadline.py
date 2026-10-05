"""DoH 的 lifetime 必须包含真实 curl 会话池的排队时间。"""

from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import fail_after

from smartdns.models.http import HTTPClientConfig
from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.curl import CurlNameserver

if TYPE_CHECKING:
    from dns.asyncbackend import Backend


@pytest.mark.parametrize("want_get", [True, False])
async def test_queue_wait_uses_dns_deadline_without_leaking_handle(
    want_get: bool,
) -> None:
    nameserver = CurlNameserver(
        CurlNameserverConfig(
            name="doh",
            type="curl",
            url="https://127.0.0.1/dns-query",
            want_get=want_get,
            fingerprint=None,
        ),
        HTTPClient(HTTPClientConfig(max_clients=1)),
    )
    await nameserver.start()
    assert nameserver._curl is not None
    session = nameserver._curl
    held = await session.pop_curl()
    try:
        # 外层测试期限显著大于 DNS lifetime；旧路径只会由测试期限终止。
        with fail_after(1) as outer:
            with pytest.raises(TimeoutError):
                await nameserver.async_query(
                    dns.message.make_query("example.com.", "A"),
                    0.1,
                    None,
                    0,
                    False,
                    cast("Backend", object()),
                )
            assert not outer.cancel_called
        assert session.pool.qsize() == 0
        session.push_curl(held)
        with fail_after(0.5):
            recovered = await session.pop_curl()
        assert recovered is held
    finally:
        session.push_curl(held)
        await nameserver.stop()
