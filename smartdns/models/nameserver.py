from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyAddress


class BaseNameserverConfig(BaseModel):
    """Nameserver 配置基类。"""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    timeout: float = Field(default=5.0, ge=0.1, description="请求超时时间（秒）")


class UDPNameserverConfig(BaseNameserverConfig):
    """UDP Nameserver 配置。"""

    type: Literal["udp"]
    address: IPvAnyAddress | str = Field(description="目标地址")
    port: int = Field(ge=1, le=65535, description="目标端口")
    repeat: int = Field(default=0, ge=0, description="请求重复次数")
    use_tricks: bool = Field(default=False, description="是否使用接收技巧")


class TCPNameserverConfig(BaseNameserverConfig):
    """TCP Nameserver 配置。"""

    type: Literal["tcp"]
    address: IPvAnyAddress | str = Field(description="目标地址")
    port: int = Field(ge=1, le=65535, description="目标端口")
    pool_size: int = Field(default=0, ge=0, description="连接池大小")
    use_tricks: bool = Field(default=False, description="是否使用发送技巧")


NameserverConfig = Annotated[
    UDPNameserverConfig | TCPNameserverConfig,
    Field(discriminator="type"),
]
