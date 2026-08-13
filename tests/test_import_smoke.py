"""导入冒烟测试：确保 smartdns 包内所有子模块均可被导入。

无既有测试的情况下，这是重构过程中最重要的安全网——任何语法错误、
未定义名、循环导入或坏引用都会在这里暴露。
"""

import importlib
import pkgutil

import smartdns


def test_all_submodules_import() -> None:
    failed: list[str] = []
    for module in pkgutil.walk_packages(smartdns.__path__, "smartdns."):
        try:
            importlib.import_module(module.name)
        except Exception as exc:
            failed.append(f"{module.name}: {exc!r}")
    assert not failed, "以下子模块导入失败:\n" + "\n".join(failed)
