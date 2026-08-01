from pydantic import BaseModel, Field


class Matcher(BaseModel):
    """规则配置类"""

    domain_include: set[str] | None = Field(default=None, description="包含的域名列表")
    domain_exclude: set[str] | None = Field(default=None, description="排除的域名列表")
    query_types: set[str] | None = Field(default=None, description="包含的类型列表")


class Rule(BaseModel):
    """规则配置类"""

    name: str = Field(description="规则名称")
    matcher: Matcher | None = Field(default=None, description="匹配器配置")
    resolver: str | None = Field(default=None, description="指定的解析器")
    before: list[str] | None = Field(default=None, description="在指定规则之前执行")
    after: list[str] | None = Field(default=None, description="在指定规则之后执行")
