"""离线工具：抓取 CDN 与 Google 的地址段，生成测速/替换用的 IP 列表。"""

from pathlib import Path
from typing import Any

import netaddr
from curl_cffi import Session
from dns.exception import DNSException
from dns.resolver import Resolver
from typer import Typer

app = Typer()
META_BASE = "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip"


def _get_text(session: Session, url: str, timeout: float) -> str:
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text


def _get_json(session: Session, url: str, timeout: float) -> dict[str, Any]:
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"响应不是 JSON object: {url}")
    return data


def _meta_ipset(session: Session, name: str, timeout: float) -> netaddr.IPSet:
    text = _get_text(session, f"{META_BASE}/{name}.list", timeout)
    return netaddr.IPSet(text.splitlines())


def _scan_networks(ipset: netaddr.IPSet, ipv4_prefix: int = 24) -> set[str]:
    result: set[str] = set()
    for cidr in ipset.iter_cidrs():
        prefix = ipv4_prefix if cidr.version == 4 else 48
        if cidr.prefixlen > prefix:
            result.add(str(cidr.supernet(prefix)[0].network))
        else:
            result.update(str(network.network) for network in cidr.subnet(prefix))
    return result


def _fastly_addresses(ipset: netaddr.IPSet) -> set[str]:
    """每个 /22（IPv6 /48）块取固定偏移处的地址；更小的网段在自身范围内取模。

    不能取超网：超网中的偏移地址可能落在原网段之外（甚至已被扣除的 cn 段）。
    """
    result: set[str] = set()
    for cidr in ipset.iter_cidrs():
        prefix, offset = (22, 485) if cidr.version == 4 else (48, 0x485)
        blocks = [cidr] if cidr.prefixlen > prefix else cidr.subnet(prefix)
        result.update(str(block[offset % block.size]) for block in blocks)
    return result


def _google_ranges(data: dict[str, Any]) -> netaddr.IPSet:
    result = netaddr.IPSet()
    for prefix in data.get("prefixes", []):
        if not isinstance(prefix, dict):
            continue
        value = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
        if value:
            result.add(value)
    return result


def _google_spf() -> netaddr.IPSet:
    result = netaddr.IPSet()
    resolver = Resolver()
    resolver.lifetime = 5
    try:
        answer = resolver.resolve("_spf.google.com", "TXT")
    except DNSException:
        return result
    for record in answer:
        text = b"".join(record.strings).decode("ascii", errors="ignore")
        for token in text.split():
            if token.startswith(("ip4:", "ip6:")):
                result.add(token[4:])
    return result


def _atomic_write(path: Path, values: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    content = "".join(f"{value}\n" for value in sorted(values))
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def fetch(output_path: Path, timeout: float = 15.0) -> dict[str, int]:
    """抓取并生成 CDN/Google 地址文件；失败时不覆盖已有结果。"""
    with Session() as session:
        cn = _meta_ipset(session, "cn", timeout)
        cloudflare = _scan_networks(_meta_ipset(session, "cloudflare", timeout) - cn)
        cloudfront = _scan_networks(_meta_ipset(session, "cloudfront", timeout) - cn)
        fastly = _fastly_addresses(_meta_ipset(session, "fastly", timeout) - cn)
        google_alt = _meta_ipset(session, "google", timeout)
        urls = [
            "https://www.gstatic.com/ipranges/goog.json",
            "https://www.gstatic.com/ipranges/cloud.json",
            "https://www.gstatic.com/ipranges/publicdns.json",
            "https://developers.google.cn/static/crawling/ipranges/common-crawlers.json",
            "https://developers.google.cn/static/crawling/ipranges/special-crawlers.json",
            "https://developers.google.cn/static/crawling/ipranges/user-triggered-fetchers.json",
            "https://developers.google.cn/static/crawling/ipranges/user-triggered-fetchers-google.json",
            "https://developers.google.cn/static/crawling/ipranges/user-triggered-agents.json",
        ]
        ranges = [_google_ranges(_get_json(session, url, timeout)) for url in urls]
        google = google_alt & ranges[0]
        for excluded in (*ranges[1:], _google_spf(), cn):
            google -= excluded
        google_values = {str(network) for network in google.iter_cidrs()}

    outputs = {
        "cloudflare.txt": cloudflare,
        "cloudfront.txt": cloudfront,
        "fastly.txt": fastly,
        "google.txt": google_values,
    }
    for filename, values in outputs.items():
        _atomic_write(output_path / filename, values)
    return {filename: len(values) for filename, values in outputs.items()}


@app.command()
def main(output_path: Path = Path("utils"), timeout: float = 15.0) -> None:
    """抓取 CDN 和 Google 地址列表。"""
    for filename, count in fetch(output_path, timeout).items():
        print(f"{filename}: {count}")


if __name__ == "__main__":
    app()
