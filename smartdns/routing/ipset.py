from pickle import load
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import IPvAnyAddress, IPvAnyNetwork


class IPSet:
    """IP列表（radix 由 utils/convert.py 离线构建，运行时只读加载）。"""

    def __init__(self):
        self._radix = None

    def load(self, path: Path):
        """从缓存文件加载IP列表"""
        if path.exists():
            with path.open("rb") as f:
                # radix 为本地可信构建产物（utils/convert.py），故用 pickle 反序列化。
                self._radix = load(f)
            logger.info(f"从{path}加载IP列表成功")

    def lookup(self, entry: str | IPvAnyNetwork | IPvAnyAddress) -> set[str]:
        """查找IP对应的标签"""
        result: set[str] = set()
        if self._radix is not None:
            nodes = self._radix.search_covering(str(entry))
            for node in nodes:
                result.update(node.data.keys())
        return result
