from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
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
    ipv4: set[IPv4Address] = Field(
        default={IPv4Address("127.0.0.1")}, description="静态返回的 IPv4 地址"
    )
    ipv6: set[IPv6Address] = Field(
        default={IPv6Address("::1")}, description="静态返回的 IPv6 地址"
    )


class ReplaceActionMap(BaseModel):
    """替换映射配置。"""

    tag: str = Field(description="替换映射的标签")
    ipv4_prefixlen: int = Field(
        default=32, ge=0, le=32, description="替换映射的 IPv4 前缀长度，默认为 32"
    )
    ipv6_prefixlen: int = Field(
        default=128, ge=0, le=128, description="替换映射的 IPv6 前缀长度，默认为 128"
    )
    ipv4: set[IPv4Address] = Field(default=set(), description="替换映射的 IPv4 地址")
    ipv6: set[IPv6Address] = Field(default=set(), description="替换映射的 IPv6 地址")


class ReplaceActionConfig(BaseActionConfig):
    """替换IP Action 配置。"""

    type: Literal["replace"]
    exclude: set[str] | None = Field(default=None, description="不进行替换的域名列表")
    replace_map: list[ReplaceActionMap] = Field(default=[], description="替换映射列表")


ActionConfig = Annotated[
    LogActionConfig | PrintActionConfig | StaticActionConfig | ReplaceActionConfig,
    Field(discriminator="type"),
]
