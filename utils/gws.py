import re
from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import aiodns
import ujson
from anyio import CapacityLimiter, create_task_group, run
from pycares import ARES_FLAG_EDNS
from typer import Typer

ip_list = defaultdict(set)
RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
# RDNS格式解析正则表达式
# IPv4格式: <dcid>-in-f<offset>.1e100.net
IPv4_REGEX = re.compile(r"^([a-z0-9-]+)-in-f(\d+)\.1e100\.net$")
# IPv6格式: <dcid>-in-x<hex-offset>.1e100.net
IPv6_REGEX = re.compile(r"^([a-z0-9-]+)-in-x([0-9a-f]{,2})([0-9a-f]{2})\.1e100\.net$")


async def resolve_ip(resolver: aiodns.DNSResolver, ip: str, limiter: CapacityLimiter):
    try:
        async with limiter:
            result = await resolver.gethostbyaddr(ip)
        ip = ip_address(ip)
        for alias in result.aliases:
            if match := IPv4_REGEX.match(alias):
                dcid, offset = match.groups()
                ip_list[dcid].add(ip - int(offset))
            elif match := IPv6_REGEX.match(alias):
                dcid, hex_offset1, hex_offset2 = match.groups()
                ip_list[dcid].add(ip - int(hex_offset1 + hex_offset2, 16))
    except Exception as e:
        print(f"Failed to resolve {ip}: {e}")


async def resolve_name(
    resolver: aiodns.DNSResolver, name: str, limiter: CapacityLimiter
):
    try:
        if match := IPv4_REGEX.match(name):
            dcid, offset = match.groups()
            offset = int(offset)
        elif match := IPv6_REGEX.match(name):
            dcid, hex_offset1, hex_offset2 = match.groups()
            offset = int(hex_offset1 + hex_offset2, 16)
        else:
            return
        async with limiter:
            result = await resolver.gethostbyname(name, aiodns.socket.AF_UNSPEC)
        for ip in result.addresses:
            ip_list[dcid].add(ip_address(ip) - offset)

    except Exception as e:
        print(f"Failed to resolve {name}: {e}")


async def start(domains: set[str] | None, ips: set[str] | None):
    r = aiodns.DNSResolver(
        nameservers=RESOLVERS, timeout=1, tries=3, rotate=True, flags=ARES_FLAG_EDNS
    )
    limiter = CapacityLimiter(200)  # 限制并发任务数为100
    async with create_task_group() as tg:
        if domains is not None:
            for domain in domains:
                tg.start_soon(resolve_name, r, domain, limiter)
        if ips is not None:
            for ip in ips:
                tg.start_soon(resolve_ip, r, ip, limiter)


app = Typer()


def default(obj):
    if isinstance(obj, set):
        return list(obj)
    if isinstance(
        obj,
        (
            IPv4Address,
            IPv6Address,
        ),
    ):
        return str(obj)
    raise TypeError(f"Unsupported type: {type(obj)}")


@app.command()
def main(
    domain: Path | None = None,
    ip: Path | None = None,
    output: Path = Path("output.json"),
):
    domains = domain.open("r").read().splitlines() if domain else None
    ips = ip.open("r").read().splitlines() if ip else None
    global ip_list
    if output.exists():
        with output.open("r") as f:
            d = ujson.load(f)
        for k, v in d.items():
            for ip in v:
                ip_list[k].add(ip_address(ip))
    run(start, domains, ips, backend_options={"use_uvloop": True})
    print(ip_list)
    with output.open("w") as f:
        ujson.dump(ip_list, f, default=default)


if __name__ == "__main__":
    app()
