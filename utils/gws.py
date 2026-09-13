import re
from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Annotated

import aiodns
import ujson
from aiodns.error import ARES_ENODATA, ARES_ENOTFOUND, DNSError
from anyio import CapacityLimiter, create_task_group, fail_after, run
from loguru import logger
from pycares import ARES_FLAG_EDNS, AAAARecordData, ARecordData
from typer import Option, Typer

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


def _register(address: Address, alias: str, results: Results) -> None:
    """登记别名推算出的数据中心基准地址；结果越界（负值）时跳过。"""
    if (parsed := _parse_name(alias)) is None:
        return
    datacenter, offset = parsed
    try:
        value = int(address) - offset
        base = (
            IPv4Address(value)
            if isinstance(address, IPv4Address)
            else IPv6Address(value)
        )
    except ValueError:
        return
    results.setdefault(datacenter, set()).add(base)


async def resolve_ip(
    resolver: aiodns.DNSResolver,
    value: str,
    limiter: CapacityLimiter,
    results: Results,
) -> None:
    try:
        address = ip_address(value)
    except ValueError as error:
        logger.warning("无效 IP {}: {}", value, error)
        return
    try:
        async with limiter:
            with fail_after(5):
                result = await resolver.gethostbyaddr(value)
    except (DNSError, OSError, TimeoutError) as error:
        logger.warning("反向解析 {} 失败: {}", value, error)
        return
    for alias in (result.name, *result.aliases):
        _register(address, alias, results)


async def _resolve_family(
    resolver: aiodns.DNSResolver,
    name: str,
    record_type: str,
    limiter: CapacityLimiter,
    results: Results,
) -> None:
    try:
        async with limiter:
            with fail_after(5):
                result = await resolver.query_dns(name, record_type)
    except DNSError as error:
        # 域名无该族记录（ENODATA/ENOTFOUND）属常态，静默跳过。
        code = error.args[0] if error.args else None
        if code not in (ARES_ENODATA, ARES_ENOTFOUND):
            logger.warning("解析 {} ({} 查询) 失败: {}", name, record_type, error)
        return
    except (OSError, TimeoutError) as error:
        logger.warning("解析 {} ({} 查询) 失败: {}", name, record_type, error)
        return
    for record in result.answer:
        if not isinstance(record.data, (ARecordData, AAAARecordData)):
            continue
        value = record.data.addr
        try:
            address = ip_address(value)
        except ValueError as error:
            logger.warning("解析 {} 返回无效地址 {}: {}", name, value, error)
            continue
        _register(address, name, results)


async def resolve_name(
    resolver: aiodns.DNSResolver,
    name: str,
    limiter: CapacityLimiter,
    results: Results,
) -> None:
    if _parse_name(name) is None:
        logger.info("跳过非 1e100.net 数据中心域名: {}", name)
        return
    async with create_task_group() as group:
        for record_type in ("A", "AAAA"):
            group.start_soon(
                _resolve_family, resolver, name, record_type, limiter, results
            )


async def collect(
    domains: set[str],
    ips: set[str],
    results: Results,
    resolvers: list[str],
) -> None:
    resolver = aiodns.DNSResolver(
        nameservers=resolvers,
        timeout=1,
        tries=3,
        rotate=True,
        flags=ARES_FLAG_EDNS,
    )
    limiter = CapacityLimiter(200)
    try:
        async with create_task_group() as task_group:
            for domain in domains:
                task_group.start_soon(resolve_name, resolver, domain, limiter, results)
            for value in ips:
                task_group.start_soon(resolve_ip, resolver, value, limiter, results)
    finally:
        await resolver.close()


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
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }


@app.command()
def main(
    domain: Path | None = None,
    ip: Path | None = None,
    output: Path = Path("output.json"),
    resolver: Annotated[
        list[str] | None, Option(help="DNS 上游服务器，可多次指定，默认公共 DNS")
    ] = None,
) -> None:
    """枚举 Google GWS 地址并合并写入 JSON。"""
    results = _load_results(output)
    run(
        collect,
        _read_lines(domain),
        _read_lines(ip),
        results,
        resolver or RESOLVERS,
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
