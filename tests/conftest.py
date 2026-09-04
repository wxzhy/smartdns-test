# 共享 pytest 夹具与配置占位。
# 后续阶段的针对性测试在此登记通用 fixture（如 mock client、样例 DNS 报文）。
import pytest

from smartdns.utils.cache_async import AnswerCache


@pytest.fixture(autouse=True)
def _isolate_shared_resolver_caches() -> None:
    """各用例运行前清空按名共享的应答缓存注册表。

    同名解析器（各 Worker 场景）与 client.resolver 内嵌解析器经
    AnswerCache.shared 共享同一实例；不清理会让先写的用例污染后者。
    """
    AnswerCache.reset_shared()
