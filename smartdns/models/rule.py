from pydantic import BaseModel, Field


class Rule(BaseModel):
    """规则配置类"""

    name: str = Field(description="规则名称")
    domain_include: set[str] | None = Field(default=None, description="包含的域名列表")
    domain_exclude: set[str] | None = Field(default=None, description="排除的域名列表")
    query_types: set[str] | None = Field(default=None, description="包含的类型列表")
    resolver: str | None = Field(default=None, description="指定的解析器")
