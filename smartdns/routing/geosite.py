
from typing import TYPE_CHECKING

from dns.name import Name, from_text
from loguru import logger
from marisa_trie import BytesTrie  # ty: ignore[unresolved-import]  C 扩展无类型 stub

if TYPE_CHECKING:
    from pathlib import Path


class GeoSite:
    """域名列表（trie 由 utils/convert.py 离线构建，运行时只读加载）。"""

    def __init__(self):
        self._trie: BytesTrie | None = None

    def load(self, path: Path):
        """从缓存文件加载域名列表"""
        if path.exists():
            self._trie = BytesTrie()
            self._trie.mmap(str(path))
            logger.info(f"从{path}加载域名列表成功，条目数: {len(self._trie)}")

    @staticmethod
    def normalize(domain: str | Name) -> str:
        """规范化域名为小写、逆序点分标签（与 trie 键构建方式一致）。"""
        if isinstance(domain, str):
            domain = from_text(domain)
        domain = domain.canonicalize()
        name = ""
        for label in reversed(domain.labels):
            name += label.decode("ascii") + "."
        return name

    def lookup(self, domain: str | Name) -> set[str]:
        """查找域名对应的标签"""
        result: set[str] = set()
        if self._trie is not None:
            key = self.normalize(domain)
            for prefix in self._trie.prefixes(key):
                for value in self._trie[prefix]:
                    result.add(value.decode("ascii"))
        return result
