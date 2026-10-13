"""GeoSite 域名标签查询：后缀、完整与关键字三类规则共存于一棵 MARISA trie。"""

from typing import TYPE_CHECKING

from dns.name import Name, from_text
from loguru import logger
from marisa_trie import BytesTrie  # ty: ignore[unresolved-import]  C 扩展无类型 stub

if TYPE_CHECKING:
    from pathlib import Path

# 规范化后原样保留的标签字节；其余字节（含 "."、"$"、非 ASCII）一律转义为
# \DDD，保证标签文本不含分隔符，键之间的前缀关系只能落在标签边界上。
_SAFE_LABEL_BYTES = b"abcdefghijklmnopqrstuvwxyz0123456789-_"
_SAFE_LABEL_SET = frozenset(_SAFE_LABEL_BYTES)
_SAFE_KEY_BYTES = _SAFE_LABEL_BYTES + b"."
# 完整匹配键 = 域名键 + 此后缀；查询时同样追加，使其只能精确命中。
FULL_SUFFIX = "$"
# 关键字键前缀；域名键总以 "." 开头（根标签在前），二者互不为前缀。
KEYWORD_PREFIX = "!"


def _label_text(label: bytes) -> str:
    if not label.translate(None, _SAFE_LABEL_BYTES):
        return label.decode("ascii")
    return "".join(
        chr(byte) if byte in _SAFE_LABEL_SET else f"\\{byte:03d}" for byte in label
    )


def _canonical(domain: str | Name) -> Name:
    if isinstance(domain, str):
        domain = from_text(domain)
    return domain.canonicalize()


def _canonical_key(name: Name) -> str:
    labels = name.labels
    raw = b".".join(reversed(labels)) + b"."
    # 快速路径：全部字节安全且点数恰为标签数（无标签内嵌 "."）时直接解码。
    if not raw.translate(None, _SAFE_KEY_BYTES) and raw.count(b".") == len(labels):
        return raw.decode("ascii")
    return "".join(f"{_label_text(label)}." for label in reversed(labels))


def domain_key(domain: str | Name) -> str:
    """后缀匹配键：小写、逆序点分标签，如 ``.com.example.``。"""
    return _canonical_key(_canonical(domain))


def full_key(domain: str | Name) -> str:
    """完整匹配键：只命中域名本身，不命中其子域名。"""
    return domain_key(domain) + FULL_SUFFIX


def keyword_key(keyword: str) -> str:
    """关键字键：对域名文本做子串匹配。"""
    return KEYWORD_PREFIX + keyword.lower()


class GeoSite:
    """域名列表（trie 由 utils/convert.py 离线构建，运行时只读加载）。

    trie 中三类键共存：后缀匹配的域名键、带 ``$`` 后缀的完整匹配键、
    以 ``!`` 开头的关键字键（加载时取出，逐个做子串匹配）。
    """

    def __init__(self):
        self._trie: BytesTrie | None = None
        self._keywords: list[tuple[bytes, frozenset[str]]] = []

    def load(self, path: Path):
        """从缓存文件加载域名列表"""
        if path.exists():
            self._trie = BytesTrie()
            self._trie.mmap(str(path))
            keywords: dict[str, set[str]] = {}
            for key, value in self._trie.items(KEYWORD_PREFIX):
                keyword = key[len(KEYWORD_PREFIX) :]
                keywords.setdefault(keyword, set()).add(value.decode("ascii"))
            self._keywords = [
                (keyword.encode("ascii"), frozenset(tags))
                for keyword, tags in keywords.items()
            ]
            logger.info(
                "从{}加载域名列表成功，条目数: {}，关键字: {}",
                path,
                len(self._trie),
                len(self._keywords),
            )

    @staticmethod
    def normalize(domain: str | Name) -> str:
        """规范化域名为小写、逆序点分标签（与 trie 键构建方式一致）。"""
        return domain_key(domain)

    def lookup(self, domain: str | Name) -> set[str]:
        """查找域名对应的标签"""
        result: set[str] = set()
        if self._trie is not None:
            name = _canonical(domain)
            # 追加完整匹配后缀：后缀域名键仍是其前缀，完整键只在精确相等时命中。
            for prefix in self._trie.prefixes(_canonical_key(name) + FULL_SUFFIX):
                for value in self._trie[prefix]:
                    result.add(value.decode("ascii"))
            if self._keywords:
                # 规范化后的原始标签字节以 "." 连接（去掉根标签），子串匹配无需转义。
                labels = name.labels
                text = b".".join(labels[:-1] if name.is_absolute() else labels)
                for keyword, tags in self._keywords:
                    if keyword in text:
                        result.update(tags)
        return result

    def close(self) -> None:
        """释放 mmap trie；底层映射随对象引用释放。"""
        self._trie = None
        self._keywords = []
