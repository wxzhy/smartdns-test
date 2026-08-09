from pydantic import BaseModel, Field


class RequestMatcher(BaseModel):
    """请求匹配器配置类"""

    domain_include: set[str] | None = Field(default=None, description="包含的域名列表")
    domain_exclude: set[str] | None = Field(default=None, description="排除的域名列表")
    query_types: set[str] | None = Field(default=None, description="包含的类型列表")


class ResponseCnameMatcher(BaseModel):
    """响应匹配器配置类"""

    cname_include: set[str] | None = Field(default=None, description="包含的CNAME列表")
    cname_exclude: set[str] | None = Field(default=None, description="排除的CNAME列表")


class ResponseIPMatcher(BaseModel):
    """响应匹配器配置类"""

    ip_include: set[str] | None = Field(default=None, description="包含的IP列表")
    ip_exclude: set[str] | None = Field(default=None, description="排除的IP列表")
    asn_include: set[str] | None = Field(default=None, description="包含的ASN列表")
    asn_exclude: set[str] | None = Field(default=None, description="排除的ASN列表")


class Rule(BaseModel):
    """规则配置类"""

    name: str = Field(description="规则名称")
    matcher: RequestMatcher | None = Field(default=None, description="匹配器配置")
    resolver: str | None = Field(default=None, description="指定的解析器")
    before: list[str] | None = Field(default=None, description="在指定规则之前执行")
    after: list[str] | None = Field(default=None, description="在指定规则之后执行")
