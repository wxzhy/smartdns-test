"""路由规则与请求/响应匹配器配置模型。"""

from dns.rdatatype import from_text, to_text
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """拒绝未知字段的配置模型基类。"""

    model_config = ConfigDict(extra="forbid")


class RequestMatcher(StrictModel):
    """请求匹配器配置类"""

    domain_include: set[str] | None = Field(default=None, description="包含的域名列表")
    domain_exclude: set[str] | None = Field(default=None, description="排除的域名列表")
    query_types: set[str] | None = Field(default=None, description="包含的类型列表")

    @field_validator("query_types")
    @classmethod
    def normalize_query_types(cls, values: set[str] | None) -> set[str] | None:
        """配置加载时规范化查询类型，运行期不再重复解析。"""
        if values is None:
            return None
        return {to_text(from_text(value.upper())) for value in values}


class ResponseCnameMatcher(StrictModel):
    """响应匹配器配置类"""

    cname_include: set[str] | None = Field(default=None, description="包含的CNAME列表")
    cname_exclude: set[str] | None = Field(default=None, description="排除的CNAME列表")


class ResponseIPMatcher(StrictModel):
    """响应匹配器配置类"""

    ip_include: set[str] | None = Field(default=None, description="包含的IP列表")
    ip_exclude: set[str] | None = Field(default=None, description="排除的IP列表")
    asn_include: set[int] | None = Field(default=None, description="包含的ASN列表")
    asn_exclude: set[int] | None = Field(default=None, description="排除的ASN列表")


class Rule(StrictModel):
    """规则配置类"""

    name: str = Field(description="规则名称")
    matcher: RequestMatcher | None = Field(default=None, description="匹配器配置")
    resolver: str | None = Field(default=None, description="指定的解析器")
    before: list[str] | None = Field(default=None, description="在指定规则之前执行")
    after: list[str] | None = Field(default=None, description="在指定规则之后执行")
