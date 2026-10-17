"""离线工具：把 geosite.dat 与自定义标签文件转换为运行时的 trie/radix 数据。"""

import pickle
from collections import defaultdict
from ipaddress import ip_network
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import ujson
from loguru import logger
from marisa_trie import BytesTrie  # ty: ignore[unresolved-import]
from radix import Radix
from typer import Option, Typer

from smartdns.routing.geosite import domain_key, full_key, keyword_key
from utils.mihomo.component.geodata.router import DomainType, GeoSiteList

if TYPE_CHECKING:
    from collections.abc import Iterator

app = Typer()

# 自定义标签文件支持与 v2fly domain-list-community 相同的前缀；无前缀为后缀匹配。
_TEXT_RULE_TYPES = {
    "domain": DomainType.Domain,
    "full": DomainType.Full,
    "keyword": DomainType.Plain,
    "regexp": DomainType.Regex,
}


def rule_key(domain_type: DomainType, value: str) -> str | None:
    """按 v2ray 语义生成 trie 键；Regex 不支持（逐条匹配代价过高），返回 None。"""
    match domain_type:
        case DomainType.Domain:
            return domain_key(value)
        case DomainType.Full:
            return full_key(value)
        case DomainType.Plain:
            return keyword_key(value)
        case _:
            return None


def _parse_text_rule(line: str) -> tuple[DomainType, str]:
    prefix, sep, value = line.partition(":")
    domain_type = _TEXT_RULE_TYPES.get(prefix.strip().lower()) if sep else None
    if domain_type is None:
        return DomainType.Domain, line
    return domain_type, value.strip()


def _display(domain_type: DomainType, value: str) -> str:
    """geosite.json 中保留规则类型，后缀匹配沿用裸域名。"""
    if domain_type == DomainType.Domain:
        return value
    prefix = {DomainType.Full: "full", DomainType.Plain: "keyword"}[domain_type]
    return f"{prefix}:{value}"


def _tag_lines(directory: Path) -> Iterator[tuple[str, str]]:
    """逐行产出 directory/*.txt 中的 (标签, 规则)；标签为小写文件名，跳过空行与注释。"""
    if not directory.is_dir():
        return
    for tag_file in directory.glob("*.txt"):
        tag = tag_file.stem.lower()
        for raw_line in tag_file.read_text(encoding="ascii").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                yield tag, line


def convert(geodata_path: Path, tag_path: Path, output_path: Path) -> None:
    """转换 GeoSite/IPSet 数据，并确保首次运行即可写出全部产物。"""
    sites: defaultdict[str, set[str]] = defaultdict(set)
    normalized_sites: defaultdict[str, set[str]] = defaultdict(set)
    radix = Radix()
    skipped_regex = 0

    def add_rule(labels: set[str], domain_type: DomainType, value: str) -> None:
        nonlocal skipped_regex
        key = rule_key(domain_type, value)
        if key is None:
            skipped_regex += 1
            return
        for label in labels:
            sites[label].add(_display(domain_type, value))
            normalized_sites[label].add(key)

    if geodata_path.is_file():
        with geodata_path.open("rb") as source:
            geosite = GeoSiteList().load(source)
        for entry in geosite.entry:
            name = entry.country_code.lower()
            for domain in entry.domain:
                # 属性以 "列表@属性"（同 geosite:google@cn）和 "@属性" 两种标签
                # 提供；不能直接用属性名，否则 @cn 会与名为 cn 的列表混为一谈。
                labels = {name}
                for attribute in domain.attribute:
                    key = attribute.key.lower()
                    labels.update((f"{name}@{key}", f"@{key}"))
                add_rule(labels, domain.type, domain.value)

    for tag, line in _tag_lines(tag_path / "geosite"):
        add_rule({tag}, *_parse_text_rule(line))

    if skipped_regex:
        logger.warning(
            "跳过 {} 条 regexp 规则（GeoSite 不支持正则匹配）", skipped_regex
        )

    for tag, line in _tag_lines(tag_path / "geoip"):
        network = ip_network(line, strict=False)
        node = radix.add(
            packed=network.network_address.packed, masklen=network.prefixlen
        )
        node.data[tag] = True

    output_path.mkdir(parents=True, exist_ok=True)
    with (output_path / "geosite.json").open("w", encoding="utf-8") as output:
        ujson.dump(sites, output, default=tuple)
    trie = BytesTrie(
        (key, label.encode("ascii"))
        for label, keys in normalized_sites.items()
        for key in keys
    )
    trie.save(str(output_path / "geosite.trie"))
    with (output_path / "geoip.radix").open("wb") as output:
        pickle.dump(radix, output)


@app.command()
def main(
    geodata_path: Annotated[Path, Option()] = Path("tags/geosite.dat"),
    tag_path: Annotated[Path, Option()] = Path("tags"),
    output_path: Annotated[Path, Option()] = Path("tags/output"),
) -> None:
    """将 GeoSite 数据转换为 SmartDNS 可用格式。"""
    convert(geodata_path, tag_path, output_path)
    print(f"转换完成，输出路径: {output_path}")


if __name__ == "__main__":
    app()
