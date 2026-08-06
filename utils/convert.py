import pickle
from collections import defaultdict
from itertools import chain, repeat
from pathlib import Path

import ujson
from dns.name import from_text
from marisa_trie import BytesTrie
from pydantic import DirectoryPath, FilePath
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from radix import Radix
from typer import Typer

from utils.mihomo.component.geodata.router import DomainType, GeoSiteList

app = Typer()


def normalize(domain: str) -> str:
    """规范化域名"""
    converted = from_text(domain)
    # 转小写
    converted = converted.canonicalize()
    name: str = ""
    for label in reversed(converted.labels):
        name += label.decode("ascii") + "."
    return name


@app.command()
def main(
    geodata_path: FilePath = Path("tags/geosite.dat"),
    tag_path: DirectoryPath = Path("tags"),
    output_path: DirectoryPath = Path("tags/output"),
):
    """将 GeoSite 数据转换为 SmartDNS 可用的格式"""
    # 读取GeoSite数据
    sites = defaultdict(set)
    radix = Radix()
    if geodata_path.exists():
        # 加载protobuf数据
        geosite = GeoSiteList().load(geodata_path.open("rb"))
        for entry in geosite.entry:
            for domain in entry.domain:
                if domain.type != DomainType.Regex:
                    normalized = normalize(domain.value)
                    sites[entry.country_code.lower()].add(normalized)
                    # 额外的标签
                    if domain.attribute:
                        for attr in domain.attribute:
                            sites[attr.key.lower()].add(normalized)
    geosite_path = tag_path / "geosite"
    if geosite_path.exists():
        for tag_file in geosite_path.glob("*.txt"):
            tag_name = tag_file.stem
            with tag_file.open("r", encoding="ascii") as f:
                for line in f:
                    if line and not line.startswith("#"):
                        normalized = normalize(line.strip())
                        sites[tag_name.lower()].add(normalized)
    geoip_path = tag_path / "geoip"
    if geoip_path.exists():
        for tag_file in geoip_path.glob("*.txt"):
            tag_name = tag_file.stem
            with tag_file.open("r", encoding="ascii") as f:
                for line in f:
                    if line and not line.startswith("#"):
                        ip = line.strip()
                        if "/" in ip:
                            ip: IPvAnyNetwork = IPvAnyNetwork(ip)
                            node = radix.add(
                                packed=ip.network_address.packed, masklen=ip.prefixlen
                            )
                        else:
                            ip = IPvAnyAddress(ip)
                            node = radix.add(packed=ip.packed)
                        node.data[tag_name.lower()] = True
    if output_path.exists():
        # print(sites)
        ujson.dump(
            sites,
            (output_path / "geosite.json").open("w", encoding="utf-8"),
            default=tuple,
        )
        tags, domains = [], []
        for k, v in sites.items():
            # 添加域名到列表中
            tags.append(repeat(k.lower().encode("ascii"), len(v)))
            domains.append(v)
        trie = BytesTrie(zip(chain(*domains), chain(*tags), strict=True))
        print(trie)
        trie.save(str(output_path / "geosite.trie"))
        pickle.dump(radix, (output_path / "geoip.radix").open("wb"))
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
    print(f"转换完成，输出路径: {output_path}")


if __name__ == "__main__":
    app()
