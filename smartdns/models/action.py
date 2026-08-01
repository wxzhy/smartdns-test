from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class BaseActionConfig(BaseModel):
    """Action 配置基类。"""

    model_config = ConfigDict(populate_by_name=True)

    name: str


class LogActionConfig(BaseActionConfig):
    """log Action 配置。"""

    type: Literal["log"]
    text: str = Field(description="日志文本")


class PrintActionConfig(BaseActionConfig):
    """Print Action 配置。"""

    type: Literal["print"]
    text: str = Field(description="打印文本")


class StaticActionConfig(BaseActionConfig):
    """静态返回 Action 配置。"""

    type: Literal["static"]
    ipv4: list[IPv4Address] = Field(
        default=[IPv4Address("127.0.0.1")], description="静态返回的 IPv4 地址"
    )
    ipv6: list[IPv6Address] = Field(
        default=[IPv6Address("::1")], description="静态返回的 IPv6 地址"
    )


ActionConfig = Annotated[
    LogActionConfig | PrintActionConfig | StaticActionConfig,
    Field(discriminator="type"),
]
