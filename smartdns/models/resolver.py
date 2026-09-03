from typing import Annotated, Literal

from pydantic import Field
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork

from smartdns.models.rule import StrictModel


class BaseResolverConfig(StrictModel):
    """Resolver 配置基类。"""

    name: str
    timeout: float = Field(default=5.0, ge=0.1, description="请求超时时间（秒）")


class PlainResolverConfig(BaseResolverConfig):
    """Plain Resolver 配置。"""

    type: Literal["plain"]
    nameservers: list[str] = Field(description="上游 nameserver 名称列表")
    cache_size: int = Field(
        default=10000,
        ge=0,
        description="应答缓存容量（按应答自身 TTL 过期，跨 Worker 共享）；0 表示关闭",
    )
    rotate: bool = Field(default=True, description="是否轮询上游nameserver")
    edns: bool = Field(default=True, description="是否启用EDNS")
    ecs: IPvAnyNetwork | None = Field(
        default=None, description="是否启用ECS，指定ECS网段"
    )
    lifetime: float = Field(default=5.0, ge=0.1, description="请求生存时间（秒）")


class AioDNSResolverConfig(BaseResolverConfig):
    """AioDNS Resolver 配置。"""

    type: Literal["aiodns"]
    nameservers: list[IPvAnyAddress] = Field(description="上游 DNS 服务器地址列表")
    port: int = Field(default=53, ge=1, le=65535, description="上游nameserver端口")
    cache_size: int = Field(default=0, ge=0, description="缓存大小")
    rotate: bool = Field(default=True, description="是否轮询上游nameserver")
    edns: bool = Field(default=True, description="是否启用EDNS")
    ecs: IPvAnyNetwork | None = Field(
        default=None, description="是否启用ECS，指定ECS网段"
    )
    tcp: bool = Field(default=False, description="是否启用TCP")
    tries: int = Field(default=5, ge=1, description="请求尝试次数")
    nodata_ttl: int = Field(
        default=300,
        ge=0,
        description="空应答（NODATA）的缓存 TTL，单位秒，0 表示不缓存",
    )


class ConcurrentResolverConfig(BaseResolverConfig):
    """Concurrent Resolver 配置。"""

    type: Literal["concurrent"]
    resolvers: list[str] = Field(description="上游resolver名称列表")
    actions: list[str] = Field(
        default_factory=list, description="请求完成后执行的动作列表"
    )
    wait_all: bool = Field(default=False, description="是否等待所有请求完成")


ResolverConfig = Annotated[
    PlainResolverConfig | AioDNSResolverConfig | ConcurrentResolverConfig,
    Field(discriminator="type"),
]
