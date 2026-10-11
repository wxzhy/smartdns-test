"""GeoSite 转换与查找须遵循 v2ray 的规则类型语义。"""

from typing import TYPE_CHECKING

from dns.name import Name

from smartdns.routing.geosite import GeoSite, domain_key
from utils.convert import convert
from utils.mihomo.component.geodata.router import (
    Domain,
    DomainAttribute,
    DomainType,
    GeoSiteList,
)
from utils.mihomo.component.geodata.router import GeoSite as GeoSiteEntry

if TYPE_CHECKING:
    from pathlib import Path


def _build(tmp_path: Path, custom: str | None = None) -> GeoSite:
    geosite = GeoSiteList(
        entry=[
            GeoSiteEntry(
                country_code="TEST",
                domain=[
                    Domain(type=DomainType.Domain, value="suffix.org"),
                    Domain(type=DomainType.Full, value="exact.example.com"),
                    Domain(type=DomainType.Plain, value="keyword"),
                    Domain(type=DomainType.Regex, value=r"^regex\d+\.net$"),
                    Domain(
                        type=DomainType.Domain,
                        value="attr.example",
                        attribute=[DomainAttribute(key="cn", bool_value=True)],
                    ),
                ],
            ),
            GeoSiteEntry(
                country_code="CN",
                domain=[Domain(type=DomainType.Domain, value="cn")],
            ),
        ]
    )
    source = tmp_path / "geosite.dat"
    source.write_bytes(bytes(geosite))
    tags = tmp_path / "tags"
    (tags / "geosite").mkdir(parents=True)
    if custom is not None:
        (tags / "geosite" / "custom.txt").write_text(custom, encoding="ascii")
    convert(source, tags, tmp_path / "output")
    result = GeoSite()
    result.load(tmp_path / "output" / "geosite.trie")
    return result


def test_domain_rule_matches_itself_and_subdomains(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    assert geosite.lookup("suffix.org") == {"test"}
    assert geosite.lookup("a.b.suffix.org") == {"test"}
    assert geosite.lookup("notsuffix.org") == set()


def test_full_rule_matches_only_exact_name(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    assert geosite.lookup("exact.example.com") == {"test"}
    assert geosite.lookup("sub.exact.example.com") == set()
    assert geosite.lookup("example.com") == set()


def test_keyword_rule_matches_substring(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    assert geosite.lookup("mykeywordsite.com") == {"test"}
    assert geosite.lookup("a.keyword.org") == {"test"}
    assert geosite.lookup("key-word.org") == set()


def test_regex_rules_are_skipped(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    assert geosite.lookup("regex1.net") == set()


def test_attributes_do_not_collide_with_list_names(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    assert geosite.lookup("www.attr.example") == {"test", "test@cn", "@cn"}
    assert geosite.lookup("example.cn") == {"cn"}


def test_custom_tag_files_accept_rule_prefixes(tmp_path: Path) -> None:
    geosite = _build(
        tmp_path,
        "# comment\nplain.example\ndomain:dom.example\n"
        "full:only.example\nkeyword:kwd\nregexp:^x$\n",
    )
    assert geosite.lookup("a.plain.example") == {"custom"}
    assert geosite.lookup("a.dom.example") == {"custom"}
    assert geosite.lookup("only.example") == {"custom"}
    assert geosite.lookup("a.only.example") == set()
    assert geosite.lookup("xkwdx.org") == {"custom"}


def test_binary_labels_are_escaped_not_rejected(tmp_path: Path) -> None:
    geosite = _build(tmp_path)
    # 非 ASCII 字节不能让查找抛 UnicodeDecodeError（客户端查询会被直接丢弃）。
    assert geosite.lookup(Name([b"\xff", b"suffix", b"org", b""])) == {"test"}
    # 标签内的 "." 不能与真正的标签边界混淆。
    assert geosite.lookup(Name([b"x.suffix", b"org", b""])) == set()
    assert domain_key(Name([b"a.b", b"com", b""])) == ".com.a\\046b."
    assert domain_key("www.Example.COM") == ".com.example.www."
