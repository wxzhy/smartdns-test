# 共享 pytest 夹具与配置占位。
# 后续阶段的针对性测试在此登记通用 fixture（如 mock client、样例 DNS 报文）。
import pytest

from smartdns.models.config import Config
from smartdns.utils.cache_async import AnswerCache


@pytest.fixture(autouse=True)
def _isolate_shared_resolver_caches() -> None:
    """各用例运行前清空按配置命名空间共享的应答缓存注册表。

    相同完整配置的解析器（各 Worker 场景）与 client.resolver 内嵌解析器经
    AnswerCache.shared 共享同一实例；不清理会让先写的用例污染后者。
    """
    AnswerCache.reset_shared()


@pytest.fixture(autouse=True)
def _isolate_config_file(tmp_path, monkeypatch) -> None:
    """Config() 默认会合并工作目录下的 config.yaml；其 geodata 路径依赖本地
    生成的文件，测试不能因此随检出环境变化。需要配置文件的用例自行指定。"""
    monkeypatch.setattr(Config, "config_file", tmp_path / "absent-config.yaml")
