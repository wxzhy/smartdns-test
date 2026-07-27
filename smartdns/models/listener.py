from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from pydantic.networks import IPvAnyAddress


class BaseListenerConfig(BaseModel):
    """Listener 配置基类。"""

    model_config = ConfigDict(populate_by_name=True)

    name: str


class Do53ListenerConfig(BaseListenerConfig):
    """UDP listener 配置。"""

    type: Literal["udp"] | Literal["tcp"]
    host: IPvAnyAddress
    port: int = Field(ge=1, le=65535)
    reuse_port: bool = False


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
