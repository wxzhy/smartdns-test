from pathlib import Path
from pickle import dump, load

from loguru import logger
from pydantic import IPvAnyAddress, IPvAnyNetwork
from radix import Radix


class IPSet:
    """IP列表"""

    def __init__(self):
        self._radix: Radix | None = None

    def load(self, path: Path):
        """从缓存文件加载IP列表"""
        if path.exists():
            with path.open("rb") as f:
                self._radix = load(f)
            logger.info(f"从{path}加载IP列表成功")

    def save(self, path: Path):
        if self._radix is not None:
            with path.open("wb") as f:
                dump(self._radix, f)
            logger.info(f"保存IP列表到{path}成功")

    def lookup(self, entry: str | IPvAnyNetwork | IPvAnyAddress) -> set[str]:
        """查找IP对应的标签"""
        result = set()
        if self._radix is not None:
            nodes = self._radix.search_covering(str(entry))
            for node in nodes:
                result.update(node.data.keys())
        return result

    def add(self, entry: str | IPvAnyNetwork | IPvAnyAddress, value: str):
        """添加IP及其标签"""
        if self._radix is not None:
            node = self._radix.add(str(entry))
            node.data[value] = True

    def remove(self, entry: str | IPvAnyNetwork | IPvAnyAddress):
        """移除IP及其标签"""
        if self._radix is not None:
            self._radix.delete(str(entry))

    def create(self, data: dict[str, set[str]]):
        """从数据字典加载IP列表"""
        self._radix = Radix()
        for k, v in data.items():
            for ip in v:
                node = self._radix.add(ip)
                node.data[k] = True
        logger.info("从数据字典加载IP列表成功")

    def clear(self):
        self._radix = None
