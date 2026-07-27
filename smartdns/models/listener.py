from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyAddress


class BaseListenerConfig(BaseModel):
    """Listener 配置基类。"""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    timeout: float = Field(default=5.0, ge=0.1, description="请求超时时间（秒）")


class Do53ListenerConfig(BaseListenerConfig):
    """UDP listener 配置。"""

    type: Literal["udp"] | Literal["tcp"]
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
