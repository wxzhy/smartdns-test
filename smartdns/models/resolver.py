from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyNetwork


class BaseResolverConfig(BaseModel):
    """Resolver 配置基类。"""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    timeout: float = Field(default=5.0, ge=0.1, description="请求超时时间（秒）")


class PlainResolverConfig(BaseResolverConfig):
    """Plain Resolver 配置。"""

    type: Literal["plain"]
    nameservers: list[str] = Field(description="上游nameserver名称列表")
    cache_size: int = Field(default=10000, description="缓存大小")
    rotate: bool = Field(default=True, description="是否轮询上游nameserver")
    edns: bool = Field(default=True, description="是否启用EDNS")
    ecs: IPvAnyNetwork | None = Field(
        default=None, description="是否启用ECS，指定ECS网段"
    )
    lifetime: float = Field(default=5.0, ge=0.1, description="请求生存时间（秒）")


class AioDNSResolverConfig(BaseResolverConfig):
    """AioDNS Resolver 配置。"""

    type: Literal["aiodns"]
    nameservers: list[str] = Field(description="上游nameserver名称列表")
    port: int = Field(default=53, ge=1, le=65535, description="上游nameserver端口")
    cache_size: int = Field(default=10000, description="缓存大小")
    rotate: bool = Field(default=True, description="是否轮询上游nameserver")
    edns: bool = Field(default=True, description="是否启用EDNS")
    lifetime: float = Field(default=5.0, ge=0.1, description="请求生存时间（秒）")


class ConcurrentResolverConfig(BaseResolverConfig):
    """Concurrent Resolver 配置。"""

    type: Literal["concurrent"]
    resolvers: list[str] = Field(description="上游resolver名称列表")


ResolverConfig = Annotated[
    PlainResolverConfig | AioDNSResolverConfig | ConcurrentResolverConfig,
    Field(discriminator="type"),
]
