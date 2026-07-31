from pydantic import BaseModel, Field


class Rule(BaseModel):
    """规则配置类"""

    name: str = Field(description="规则名称")
    type: str = Field(description="规则类型")
    value: str = Field(description="规则值")
