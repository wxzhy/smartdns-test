from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, ClassVar, Literal

from pydantic import Field

from smartdns.models.rule import RequestMatcher, ResponseIPMatcher, StrictModel

# Action 可挂载的阶段：路由 before（on_request）、路由 after（on_response /
# on_subquery）、ConcurrentResolver actions（on_resolver）。
type ActionPhase = Literal["before", "after", "resolver"]


class BaseActionConfig(StrictModel):
    """Action 配置基类。"""

    # 实现了对应 hook 的阶段；放到其他阶段时 hook 为空操作，配置加载即报错。
    phases: ClassVar[frozenset[ActionPhase]] = frozenset()

    name: str


class LogActionConfig(BaseActionConfig):
    """log Action 配置。"""

    type: Literal["log"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"before"})
    text: str = Field(description="日志文本")


class StaticActionConfig(BaseActionConfig):
    """静态返回 Action 配置。"""

    type: Literal["static"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"before"})
    ipv4: set[IPv4Address] = Field(
        default_factory=lambda: {IPv4Address("127.0.0.1")},
        description="静态返回的 IPv4 地址",
    )
    ipv6: set[IPv6Address] = Field(
        default_factory=lambda: {IPv6Address("::1")},
        description="静态返回的 IPv6 地址",
    )
    ttl: int = Field(
        default=86400, ge=0, description="静态应答的 TTL（秒），默认 86400"
    )


class ReplaceActionMap(StrictModel):
    """替换映射配置。"""

    match_ip: ResponseIPMatcher = Field(description="替换映射的标签")
    ipv4_prefixlen: int = Field(
        default=32, ge=0, le=32, description="替换映射的 IPv4 前缀长度，默认为 32"
    )
    ipv6_prefixlen: int = Field(
        default=128, ge=0, le=128, description="替换映射的 IPv6 前缀长度，默认为 128"
    )
    ipv4: set[IPv4Address] | None = Field(
        default=None, description="替换映射的 IPv4 地址"
    )
    ipv6: set[IPv6Address] | None = Field(
        default=None, description="替换映射的 IPv6 地址"
    )


class ReplaceActionConfig(BaseActionConfig):
    """替换IP Action 配置。"""

    type: Literal["replace"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"resolver"})
    match_name: RequestMatcher = Field(description="替换IP操作的请求匹配器")
    replace_map: list[ReplaceActionMap] = Field(
        default_factory=list, description="替换映射列表"
    )


class HTTPSActionConfig(BaseActionConfig):
    """HTTPS Action 配置。"""

    type: Literal["https"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"after"})
    remove_hint: bool = Field(
        default=True, description="是否移除 HTTPS 中的 ipv4/ipv6 hint 参数"
    )
    remove_h3: bool = Field(
        default=True, description="是否移除 HTTPS ALPN 中的 h3 参数"
    )
    add_ech: bool = Field(default=True, description="是否添加 HTTPS 中的 ech 参数")
    enable_subquery: bool = Field(
        default=True, description="无 IP hint 或 HTTPS 空应答时是否发起 A 子查询"
    )
    match_name: RequestMatcher = Field(description="匹配的域名")
    match_ip: ResponseIPMatcher = Field(description="匹配的IP地址")
    ech_domain: str = Field(
        default="crypto.cloudflare.com",
        description="用于查询 ECHConfig 的域名",
    )


class FallbackMap(StrictModel):
    """Fallback 映射配置。"""

    match_name: RequestMatcher = Field(description="匹配的域名")
    ipv4: set[IPv4Address] | None = Field(
        default=None,
        description="静态返回的 IPv4 地址",
    )
    ipv6: set[IPv6Address] | None = Field(
        default=None, description="静态返回的 IPv6 地址"
    )
    ttl: int = Field(
        default=86400, ge=0, description="静态应答的 TTL（秒），默认 86400"
    )


class PingConfig(StrictModel):
    """ping 测速配置。"""

    ping: bool = Field(default=True, description="是否启用ping测速")
    privileged: bool = Field(
        default=True, description="是否使用需要系统权限的原始 ICMP socket"
    )
    port: set[int] | None = Field(
        default=None, description="测速端口列表，空表示不测速"
    )
    timeout: float = Field(default=0.3, ge=0.1, description="测速超时时间（秒）")


class SpeedcheckActionConfig(BaseActionConfig):
    """Speedcheck 配置。"""

    type: Literal["speedcheck"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"resolver", "after"})
    ping_config: PingConfig = Field(default_factory=PingConfig, description="测速配置")
    match_ip: ResponseIPMatcher = Field(
        default_factory=ResponseIPMatcher, description="测速匹配器"
    )
    tag_multipliers: dict[str, Annotated[float, Field(gt=0, allow_inf_nan=False)]] = (
        Field(
            default_factory=dict,
            description="IP 标签对应的倍率；按配置顺序采用首个命中的标签",
        )
    )
    asn_multipliers: dict[int, Annotated[float, Field(gt=0, allow_inf_nan=False)]] = (
        Field(
            default_factory=dict,
            description="未命中标签倍率时使用的 ASN 倍率；均未命中时为 1",
        )
    )
    max_num: int = Field(default=1, ge=1, description="排序后保留的IP最大数量")
    threshold: float = Field(
        default=100.0,
        ge=0.0,
        description="加权 RTT 延迟阈值（毫秒）；无有效 RTT 时忽略",
    )


class FallbackActionConfig(BaseActionConfig):
    """Fallback Action 配置。"""

    type: Literal["fallback"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"after"})
    map: list[FallbackMap] = Field(
        default_factory=list, description="Fallback 映射列表"
    )


class FilterItem(StrictModel):
    """Filter 映射配置。"""

    match_name: RequestMatcher = Field(description="匹配的域名")
    match_ip: ResponseIPMatcher = Field(description="匹配的IP地址")


class FilterActionConfig(BaseActionConfig):
    """Filter Action 配置。"""

    type: Literal["filter"]
    phases: ClassVar[frozenset[ActionPhase]] = frozenset({"resolver"})
    filters: list[FilterItem] = Field(
        default_factory=list, description="Filter 映射列表"
    )


ActionConfig = Annotated[
    LogActionConfig
    | StaticActionConfig
    | ReplaceActionConfig
    | HTTPSActionConfig
    | FallbackActionConfig
    | SpeedcheckActionConfig
    | FilterActionConfig,
    Field(discriminator="type"),
]
