import pickle
from collections import defaultdict
from ipaddress import ip_network
from itertools import chain, repeat
from pathlib import Path
from typing import Annotated

import ujson
from dns.name import from_text
from marisa_trie import BytesTrie  # ty: ignore[unresolved-import]
from radix import Radix
from typer import Option, Typer

from utils.mihomo.component.geodata.router import DomainType, GeoSiteList

app = Typer()


def normalize(domain: str) -> str:
    """将域名规范化为 GeoSite Trie 使用的逆序标签形式。"""
    name = from_text(domain).canonicalize()
    return "".join(f"{label.decode('ascii')}." for label in reversed(name.labels))


def convert(geodata_path: Path, tag_path: Path, output_path: Path) -> None:
    """转换 GeoSite/IPSet 数据，并确保首次运行即可写出全部产物。"""
    sites: defaultdict[str, set[str]] = defaultdict(set)
    normalized_sites: defaultdict[str, set[str]] = defaultdict(set)
    radix = Radix()
    if geodata_path.is_file():
        with geodata_path.open("rb") as source:
            geosite = GeoSiteList().load(source)
        for entry in geosite.entry:
            for domain in entry.domain:
                if domain.type == DomainType.Regex:
                    continue
                labels = {entry.country_code.lower()}
                labels.update(attribute.key.lower() for attribute in domain.attribute)
                normalized = normalize(domain.value)
                for label in labels:
                    sites[label].add(domain.value)
                    normalized_sites[label].add(normalized)

    geosite_path = tag_path / "geosite"
    if geosite_path.is_dir():
        for tag_file in geosite_path.glob("*.txt"):
            for raw_line in tag_file.read_text(encoding="ascii").splitlines():
                line = raw_line.strip()
                if line and not line.startswith("#"):
                    normalized_sites[tag_file.stem.lower()].add(normalize(line))

    geoip_path = tag_path / "geoip"
    if geoip_path.is_dir():
        for tag_file in geoip_path.glob("*.txt"):
            for raw_line in tag_file.read_text(encoding="ascii").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                network = ip_network(line, strict=False)
                node = radix.add(
                    packed=network.network_address.packed,
                    masklen=network.prefixlen,
                )
                node.data[tag_file.stem.lower()] = True

    output_path.mkdir(parents=True, exist_ok=True)
    with (output_path / "geosite.json").open("w", encoding="utf-8") as output:
        ujson.dump(sites, output, default=tuple)
    tags, domains = [], []
    for label, values in normalized_sites.items():
        tags.append(repeat(label.encode("ascii"), len(values)))
        domains.append(values)
    trie = BytesTrie(zip(chain(*domains), chain(*tags), strict=True))
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
