"""CurlNameserver 指纹模拟（fingerprint → curl-cffi impersonate）测试。

配置默认保持既有行为（chrome）；显式指纹透传给独占会话；null 关闭模拟；
未知指纹在配置加载期被校验器拒绝。
"""

from typing import TYPE_CHECKING, cast

import pytest
from curl_cffi import AsyncSession
from pydantic import ValidationError

from smartdns.models.http import HTTPClientConfig
from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.curl import CurlNameserver

if TYPE_CHECKING:
    from smartdns.nameservers.client import HTTPClient as HTTPClientType


class _RecordingClient:
    """记录 create_session 实参的最小 HTTPClient 替身。"""

    def __init__(self) -> None:
        self.impersonates: list[str | None] = []

    def create_session(self, extra_options=None, impersonate="chrome") -> object:
        self.impersonates.append(impersonate)
        return object()

    def resolve_entries(self, port: int) -> list[str]:
        return []


async def _start_nameserver(fingerprint: str | None) -> _RecordingClient:
    config = CurlNameserverConfig(
        name="a",
        type="curl",
        url="https://a.example/dns-query",
        fingerprint=fingerprint,
    )
    client = _RecordingClient()
    nameserver = CurlNameserver(config, cast("HTTPClientType", client))
    # 启动即创建会话；无网络请求，指纹仅是会话参数。
    await nameserver.start()
    return client


async def test_default_fingerprint_is_chrome() -> None:
    # 未配置 fingerprint 时保持既有默认行为。
    config = CurlNameserverConfig(
        name="a", type="curl", url="https://a.example/dns-query"
    )
    assert config.fingerprint == "chrome"
    client = await _start_nameserver(config.fingerprint)
    assert client.impersonates == ["chrome"]


async def test_fingerprint_passed_to_session() -> None:
    client = await _start_nameserver("safari")
    assert client.impersonates == ["safari"]


async def test_null_fingerprint_disables_impersonation() -> None:
    client = await _start_nameserver(None)
    assert client.impersonates == [None]


async def test_real_session_carries_impersonate() -> None:
    """真实 HTTPClient 创建的会话应携带指定的 impersonate 目标。"""
    client = HTTPClient(config=HTTPClientConfig())
    session = client.create_session(impersonate="safari")
    assert isinstance(session, AsyncSession)
    assert session.impersonate == "safari"
    assert client.create_session(impersonate=None).impersonate is None


def test_config_rejects_unknown_fingerprint() -> None:
    with pytest.raises(ValidationError, match="未知的 curl-cffi 指纹"):
        CurlNameserverConfig(
            name="a",
            type="curl",
            url="https://a.example/dns-query",
            fingerprint="bogus-browser",
        )


def test_config_accepts_alias_and_versioned_targets() -> None:
    for fingerprint in ("chrome", "chrome131", "safari", "firefox", "safari_ios"):
        config = CurlNameserverConfig(
            name="a",
            type="curl",
            url="https://a.example/dns-query",
            fingerprint=fingerprint,
        )
        assert config.fingerprint == fingerprint
