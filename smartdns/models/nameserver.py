from typing import Annotated, Literal

from curl_cffi.requests.impersonate import (
    BrowserType,
    resolve_latest_browser_type,
)
from pydantic import Field, field_validator
from pydantic.networks import HttpUrl, IPvAnyAddress

from smartdns.models.rule import StrictModel
from smartdns.nameservers._dnscrypt import parse_stamp


class BaseNameserverConfig(StrictModel):
    """Nameserver 配置基类。"""

    name: str
    timeout: float = Field(
        default=5.0, ge=0.1, description="单次上游查询超时上限（秒）"
    )


class AddressNameserverConfig(BaseNameserverConfig):
    """基于地址+端口的 Do53 Nameserver 配置基类（UDP/TCP 共用）。"""

    address: IPvAnyAddress | str = Field(description="目标地址")
    port: int = Field(ge=1, le=65535, description="目标端口")


class UDPNameserverConfig(AddressNameserverConfig):
    """UDP Nameserver 配置。"""

    type: Literal["udp"]
    repeat: int = Field(default=0, ge=0, description="请求重复次数")
    use_tricks: bool = Field(default=False, description="是否使用接收技巧")


class TCPNameserverConfig(AddressNameserverConfig):
    """TCP Nameserver 配置。"""

    type: Literal["tcp"]
    pool_size: int = Field(default=0, ge=0, description="连接池大小")
    use_tricks: bool = Field(default=False, description="是否使用发送技巧")


class TLSNameserverConfig(AddressNameserverConfig):
    """TLS (DNS over TLS) Nameserver 配置。"""

    type: Literal["tls"]
    port: int = Field(
        default=853, ge=1, le=65535, description="目标端口，默认 DoT 标准端口 853"
    )
    server_name: str | None = Field(
        default=None,
        description="TLS SNI 与证书验证锚点；域名地址缺省取自身，IP 不发送 SNI",
    )
    fingerprint: str | None = Field(
        default="chrome:stable",
        description="utls TLS 指纹预设（如 chrome:stable）；null 表示标准 ClientHello",
    )
    verify: bool = Field(default=True, description="是否验证 TLS 证书")
    pool_size: int = Field(default=0, ge=0, description="连接池大小")


class DNSCryptNameserverConfig(BaseNameserverConfig):
    """DNSCrypt（协议 2，XChaCha20-Poly1305）Nameserver 配置。"""

    type: Literal["dnscrypt"]
    stamp: str = Field(
        description="DNSCrypt sdns:// stamp（含地址、端口、提供者名称与 Ed25519 公钥）"
    )
    tcp_only: bool = Field(default=False, description="是否强制使用 TCP")
    pool_size: int = Field(
        default=0, ge=0, description="已弃用，DNSCrypt TCP 每次查询都新建连接"
    )

    @field_validator("stamp")
    @classmethod
    def check_stamp(cls, value: str) -> str:
        """配置加载期解析 stamp，提前暴露格式错误。"""
        parse_stamp(value)
        return value


class CurlNameserverConfig(BaseNameserverConfig):
    """Curl Nameserver 配置。"""

    type: Literal["curl"]
    url: HttpUrl = Field(description="目标url地址")
    host: str | None = Field(default=None, description="请求Host头")
    want_get: bool = Field(default=False, description="是否使用GET请求")
    verify: bool = Field(default=True, description="是否验证SSL证书")
    ech: bool | str = Field(
        default=True, description="是否使用ECH请求，或指定ECH密钥的域名"
    )
    fingerprint: str | None = Field(
        default="chrome",
        description="curl-cffi 指纹模拟目标（如 chrome131、safari）；null 表示不模拟",
    )

    @field_validator("fingerprint")
    @classmethod
    def check_fingerprint(cls, value: str | None) -> str | None:
        """按 curl-cffi 自身的解析规则在配置加载期校验指纹目标。

        合法值为 BrowserType 枚举成员（版本化目标如 chrome131）或
        resolve_latest_browser_type 认识的别名（chrome/safari/firefox 等）。
        """
        if value is None:
            return value
        if value in {item.value for item in BrowserType}:
            return value
        if resolve_latest_browser_type(value) != value:
            return value
        raise ValueError(f"未知的 curl-cffi 指纹 {value!r}")


NameserverConfig = Annotated[
    UDPNameserverConfig
    | TCPNameserverConfig
    | TLSNameserverConfig
    | DNSCryptNameserverConfig
    | CurlNameserverConfig,
    Field(discriminator="type"),
]
