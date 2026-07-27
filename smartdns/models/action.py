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


ActionConfig = Annotated[
    LogActionConfig | PrintActionConfig,
    Field(discriminator="type"),
]
