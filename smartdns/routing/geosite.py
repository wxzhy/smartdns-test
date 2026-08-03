from itertools import chain, repeat
from pathlib import Path

from dns.name import Name, from_text
from loguru import logger
from marisa_trie import BytesTrie


class GeoSite:
    """域名列表"""

    def __init__(self):
        self._trie: BytesTrie | None = None

    def load(self, path: Path):
        """从缓存文件加载域名列表"""
        if path.exists():
            self._trie = BytesTrie()
            self._trie.mmap(str(path))
            # self._trie.load(str(path))
            logger.info(f"从{path}加载域名列表成功，条目数: {len(self._trie)}")

    def save(self, path: Path):
        """保存域名列表到缓存文件"""
        if self._trie is not None:
            self._trie.save(str(path))
            logger.info(f"保存域名列表到{path}成功，条目数: {len(self._trie)}")

    @staticmethod
    def normalize(domain: str | Name) -> str:
        """规范化域名"""
        if isinstance(domain, str):
            domain = from_text(domain)
        # 转小写
        domain = domain.canonicalize()
        name: str = ""
        for label in reversed(domain.labels):
            name += label.decode("ascii") + "."
        return name

    def lookup(self, domain: str | Name) -> set[str]:
        """查找域名对应的标签"""
        result = set()
        if self._trie is not None:
            domain = self.normalize(domain)
            for key in self._trie.prefixes(domain):
                for value in self._trie[key]:
                    result.add(value.decode("ascii"))
        return result

    def create(self, data: dict[str, set[str]]):
        """创建域名列表"""
        self._trie = BytesTrie()
        tags, domains = [], []
        for k, v in data.items():
            # 添加域名到列表中
            tags.append(repeat(k.encode("ascii"), len(v)))
            domains.append(v)
        self._trie = BytesTrie(zip(chain(*domains), chain(*tags), strict=True))
        logger.info(f"创建域名列表成功，条目数: {len(self._trie)}")
