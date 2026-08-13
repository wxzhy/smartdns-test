import re
from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import aiodns
import ujson
from anyio import CapacityLimiter, create_task_group, fail_after, run
from loguru import logger
from pycares import ARES_FLAG_EDNS
from typer import Typer

type Address = IPv4Address | IPv6Address
type Results = dict[str, set[Address]]
RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
IPV4_PATTERN = re.compile(r"^([a-z0-9-]+)-in-f(\d+)\.1e100\.net$")
IPV6_PATTERN = re.compile(
    r"^([a-z0-9-]+)-in-x([0-9a-f]{0,2})([0-9a-f]{2})\.1e100\.net$"
)
app = Typer()


def _parse_name(name: str) -> tuple[str, int] | None:
    if match := IPV4_PATTERN.match(name):
        datacenter, offset = match.groups()
        return datacenter, int(offset)
    if match := IPV6_PATTERN.match(name):
        datacenter, high, low = match.groups()
        return datacenter, int(high + low, 16)
    return None


def _subtract(address: Address, offset: int) -> Address:
    return ip_address(int(address) - offset)


async def resolve_ip(
    resolver: aiodns.DNSResolver,
    value: str,
    limiter: CapacityLimiter,
    results: Results,
) -> None:
    try:
        async with limiter:
            with fail_after(5):
                result = await resolver.gethostbyaddr(value)
        address = ip_address(value)
        for alias in result.aliases:
            if parsed := _parse_name(alias):
                datacenter, offset = parsed
                results.setdefault(datacenter, set()).add(_subtract(address, offset))
    except (OSError, TimeoutError, ValueError) as error:
        logger.warning("反向解析 {} 失败: {}", value, error)


async def resolve_name(
    resolver: aiodns.DNSResolver,
    name: str,
    limiter: CapacityLimiter,
    results: Results,
) -> None:
    parsed = _parse_name(name)
    if parsed is None:
        return
    datacenter, offset = parsed
    try:
        async with limiter:
            with fail_after(5):
                result = await resolver.gethostbyname(name, aiodns.socket.AF_UNSPEC)
        results.setdefault(datacenter, set()).update(
            _subtract(ip_address(value), offset) for value in result.addresses
        )
    except (OSError, TimeoutError, ValueError) as error:
        logger.warning("解析 {} 失败: {}", name, error)


async def collect(domains: set[str], ips: set[str], results: Results) -> None:
    resolver = aiodns.DNSResolver(
        nameservers=RESOLVERS,
        timeout=1,
        tries=3,
        rotate=True,
        flags=ARES_FLAG_EDNS,
    )
    limiter = CapacityLimiter(200)
    async with create_task_group() as task_group:
        for domain in domains:
            task_group.start_soon(resolve_name, resolver, domain, limiter, results)
        for value in ips:
            task_group.start_soon(resolve_ip, resolver, value, limiter, results)


def _load_results(path: Path) -> Results:
    results: defaultdict[str, set[Address]] = defaultdict(set)
    if not path.is_file():
        return results
    with path.open("r", encoding="utf-8") as source:
        data = ujson.load(source)
    for datacenter, values in data.items():
        results[datacenter].update(ip_address(value) for value in values)
    return results


def _read_lines(path: Path | None) -> set[str]:
    if path is None:
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


@app.command()
def main(
    domain: Path | None = None,
    ip: Path | None = None,
    output: Path = Path("output.json"),
) -> None:
    """枚举 Google GWS 地址并合并写入 JSON。"""
    results = _load_results(output)
    run(
        collect,
        _read_lines(domain),
        _read_lines(ip),
        results,
        backend_options={"use_uvloop": True},
    )
    serializable = {
        key: sorted(str(address) for address in values)
        for key, values in sorted(results.items())
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as target:
        ujson.dump(serializable, target, ensure_ascii=False, indent=2)
    temporary.replace(output)


if __name__ == "__main__":
    app()
