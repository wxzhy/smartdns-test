from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class BaseActionConfig(BaseModel):
    """Action 配置基类。"""

    name: str


class LogActionConfig(BaseActionConfig):
    """log Action 配置。"""

    type: Literal["log"]
    text: str = Field(description="日志文本")


class StaticActionConfig(BaseActionConfig):
    """静态返回 Action 配置。"""

    type: Literal["static"]
    ipv4: set[IPv4Address] = Field(
        default_factory=lambda: {IPv4Address("127.0.0.1")},
        description="静态返回的 IPv4 地址",
    )
    ipv6: set[IPv6Address] = Field(
        default_factory=lambda: {IPv6Address("::1")},
        description="静态返回的 IPv6 地址",
    )


class ReplaceActionMap(BaseModel):
    """替换映射配置。"""

    tag: set[str] = Field(description="替换映射的标签")
    ipv4_prefixlen: int = Field(
        default=32, ge=0, le=32, description="替换映射的 IPv4 前缀长度，默认为 32"
    )
    ipv6_prefixlen: int = Field(
        default=128, ge=0, le=128, description="替换映射的 IPv6 前缀长度，默认为 128"
    )
    ipv4: set[IPv4Address] = Field(
        default_factory=set, description="替换映射的 IPv4 地址"
    )
    ipv6: set[IPv6Address] = Field(
        default_factory=set, description="替换映射的 IPv6 地址"
    )


class ReplaceActionConfig(BaseActionConfig):
    """替换IP Action 配置。"""

    type: Literal["replace"]
    exclude: set[str] | None = Field(default=None, description="不进行替换的域名列表")
    replace_map: list[ReplaceActionMap] = Field(
        default_factory=list, description="替换映射列表"
    )


class HTTPSActionConfig(BaseActionConfig):
    """HTTPS Action 配置。"""

    type: Literal["https"]
    remove_hint: bool = Field(
        default=True, description="是否移除 HTTPS 中的 ipv4/ipv6 hint 参数"
    )
    remove_h3: bool = Field(
        default=True, description="是否移除 HTTPS ALPN 中的 h3 参数"
    )
    add_ech: bool = Field(default=True, description="是否添加 HTTPS 中的 ech 参数")
    exclude: set[str] | None = Field(default=None, description="不进行添加的域名列表")
    tag: set[str] = Field(description="匹配的标签")
    ech_domain: str = Field(
        default="crypto.cloudflare.com",
        description="ECH 域名，表示使用请求的域名",
    )


class FallbackMap(BaseModel):
    """Fallback 映射配置。"""

    domain_include: set[str] = Field(description="Fallback 映射的标签")
    ip_include: set[str] = Field(description="Fallback 映射的IP地址")
    ipv4: set[IPv4Address] | None = Field(
        default=None,
        description="静态返回的 IPv4 地址",
    )
    ipv6: set[IPv6Address] | None = Field(
        default_factory=set,
        description="静态返回的 IPv6 地址",
    )


class SpeedtestConfig(BaseModel):
    """Speedtest 配置。"""

    ping: bool = Field(default=True, description="是否启用ping测速")
    port: set[int] | None = Field(
        default=None, description="测速端口列表，空表示不测速"
    )
    timeout: float = Field(default=0.5, ge=0.1, description="测速超时时间（秒）")


class FallbackActionConfig(BaseActionConfig):
    """Fallback Action 配置。"""

    type: Literal["fallback"]
    ping: bool = Field(default=True, description="是否启用ping检测")
    exclude: set[str] | None = Field(
        default=None, description="不进行ping检测的域名列表"
    )
    speedtest: SpeedtestConfig = Field(
        default_factory=SpeedtestConfig, description="测速配置"
    )
    map: list[FallbackMap] = Field(
        default_factory=list, description="Fallback 映射列表"
    )


ActionConfig = Annotated[
    LogActionConfig
    | StaticActionConfig
    | ReplaceActionConfig
    | HTTPSActionConfig
    | FallbackActionConfig,
    Field(discriminator="type"),
]
