from typing import Annotated, Literal

from pydantic import Field
from pydantic.networks import IPvAnyAddress

from smartdns.models.rule import StrictModel


class BaseListenerConfig(StrictModel):
    """Listener 配置基类。"""

    name: str
    timeout: float = Field(default=5.0, ge=0.1, description="请求超时时间（秒）")


class Do53ListenerConfig(BaseListenerConfig):
    """Do53（UDP/TCP）listener 配置。"""

    type: Literal["udp", "tcp"]
    host: IPvAnyAddress | None = Field(description="监听地址", default=None)
    port: int = Field(ge=1, le=65535, description="监听端口")
    reuse_port: bool = Field(default=False, description="是否启用端口复用")


class HTTPListenerConfig(BaseListenerConfig):
    """HTTP（DoH）listener 配置。"""

    type: Literal["http"]
    host: IPvAnyAddress
    port: int = Field(ge=1, le=65535)
    path: str = "/dns-query"


ListenerConfig = Annotated[
    Do53ListenerConfig | HTTPListenerConfig,
    Field(discriminator="type"),
]
