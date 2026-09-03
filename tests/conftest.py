# 共享 pytest 夹具与配置占位。
# 后续阶段的针对性测试在此登记通用 fixture（如 mock client、样例 DNS 报文）。
import pytest

from smartdns.resolvers.plain import _reset_resolver_caches


@pytest.fixture(autouse=True)
def _isolate_shared_resolver_caches() -> None:
    """各用例运行前清空 PlainResolver 的跨线程共享应答缓存。

    缓存以解析器名为键注册在模块级注册表中，同名的不同测试解析器
    实例会共享同一 cachetools 实例；不清理会让先写的用例污染后者。
    """
    _reset_resolver_caches()
