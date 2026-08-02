from pydantic import BaseModel, Field
from pydantic.networks import HttpUrl, IPvAnyAddress

from smartdns.models.resolver import AioDNSResolverConfig


class HTTPClientConfig(BaseModel):
    """HTTP 客户端配置"""

    # dns_servers: list[IPvAnyAddress] | None = Field(
    #     default=None, description="HTTP客户端使用的DNS服务器列表"
    # )
    # dns_port: int = Field(default=53, ge=1, le=65535, description="DNS服务器端口")
    # edns: bool = Field(default=True, description="是否启用EDNS")
    # tcp_dns: bool = Field(default=False, description="是否使用TCP DNS解析")
    resolver: AioDNSResolverConfig | None = Field(
        default=None, description="HTTP客户端使用的上游DNS解析器配置"
    )
    max_clients: int = Field(default=65536, ge=0, description="HTTP客户端的最大连接数")
    hosts: list[tuple[str, IPvAnyAddress]] | None = Field(
        default=None, description="自定义hosts映射列表"
    )
    dns_cache_ttl: int = Field(default=300, ge=0, description="DNS缓存的TTL，单位为秒")
    shuffle: bool = Field(default=True, description="是否随机打乱IP列表")
    doh: HttpUrl | None = Field(
        default=None, description="DNS over HTTPS (DoH) 服务器地址"
    )
    doh_verify: bool = Field(default=True, description="是否验证DoH服务器的SSL证书")
