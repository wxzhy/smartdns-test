"""Worker 内的 HTTP 客户端：创建 curl-cffi 会话，并查询、缓存 ECHConfig。"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address
from time import time
from typing import TYPE_CHECKING

from curl_cffi import AsyncSession, CurlHttpVersion, CurlOpt
from dns.name import Name, from_text
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from loguru import logger

from smartdns.resolvers.aiodns import AioDNSResolver
from smartdns.utils.cache_async import CacheSlot, cached

if TYPE_CHECKING:
    from smartdns.models.config import HTTPClientConfig


@dataclass(frozen=True)
class ECHResult:
    value: str | None
    expiration: float


# ECH 结果缓存由 Master 启动时绑定；值与来源 TTL 均为跨线程安全的不可变数据。
ECH_CACHE: CacheSlot[str, ECHResult] = CacheSlot()
set_ech_cache = ECH_CACHE.bind


def _ech_cache_key(client: object, domain: str | Name) -> str:
    """ECH 缓存键为域名规范化文本，全局共享，不含实例标识。"""
    if isinstance(domain, str):
        domain = from_text(domain)
    return domain.canonicalize().to_text()


class HTTPClient:
    def __init__(self, config: HTTPClientConfig):
        self.config = config
        self.resolver: AioDNSResolver | None = (
            AioDNSResolver(config=config.resolver)
            if config.resolver is not None
            else None
        )

    async def start(self):
        """启动HTTP客户端。

        curl 会话不再在此集中创建；每个 CurlNameserver 通过 create_session()
        独立持有一个会话，避免共享可变状态（逐请求修改 ECH 选项）导致的竞态。
        """
        logger.info(
            "启动 HTTP 客户端，ECH 引导解析器: {}",
            self.resolver.name if self.resolver is not None else "未配置",
        )
        if self.resolver is not None:
            await self.resolver.start()

    async def stop(self) -> None:
        """停止HTTP客户端（停止内置解析器；curl 会话由各 CurlNameserver 自行关闭）。"""
        logger.info("停止 HTTP 客户端")
        if self.resolver is not None:
            await self.resolver.stop()

    def _base_curl_options(self) -> dict[CurlOpt, object]:
        """构建基础 curl 选项（DOH / DNS 缓存；RESOLVE 按上游端口注入）。"""
        opt: dict[CurlOpt, object] = {}
        if self.config.doh is not None:
            opt[CurlOpt.DOH_URL] = str(self.config.doh)
            opt[CurlOpt.DOH_SSL_VERIFYPEER] = int(self.config.doh_verify)
        opt[CurlOpt.DNS_CACHE_TIMEOUT] = self.config.dns_cache_ttl
        opt[CurlOpt.DNS_SHUFFLE_ADDRESSES] = 1 if self.config.shuffle else 0
        return opt

    def resolve_entries(self, port: int) -> list[str]:
        """同一 host:port 的全部地址必须位于一个 RESOLVE 条目中。"""
        if not self.config.hosts:
            return []
        entries = []
        for host in sorted(self.config.hosts):
            addresses = []
            for ip in sorted(
                self.config.hosts[host],
                key=lambda address: (address.version, int(address)),
            ):
                if isinstance(ip, IPv6Address):
                    addresses.append(f"[{ip}]")
                else:
                    addresses.append(str(ip))
            if addresses:
                entries.append(f"{host}:{port}:{','.join(addresses)}")
        return entries

    def create_session(
        self,
        extra_options: dict[CurlOpt, object] | None = None,
        impersonate: str | None = "chrome",
    ) -> AsyncSession:
        """创建一个独立的 AsyncSession。

        每个 CurlNameserver 各持一个，避免共享会话被逐请求修改 curl_options[ECH]
        导致的并发竞态与跨上游污染；impersonate 指定 TLS/HTTP2 指纹模拟目标，
        None 表示不模拟。
        """
        opt = self._base_curl_options()
        if extra_options:
            opt.update(extra_options)
        return AsyncSession(
            headers={"Accept": "application/dns-message"},
            max_clients=self.config.max_clients,
            http_version=CurlHttpVersion.V2TLS,
            default_headers=True,
            impersonate=impersonate,
            curl_options=opt,
        )

    async def get_ech_key(self, domain: str | Name) -> str | None:
        result = await self.get_ech_result(domain)
        return result.value if result is not None else None

    async def get_ech_result(self, domain: str | Name) -> ECHResult | None:
        """临时失败不落库；成功与真实无 ECH 结果按来源应答 TTL 缓存。"""
        if self.resolver is None:
            raise ValueError("HTTP客户端未配置上游DNS解析器")
        try:
            return await self._resolve_ech(domain)
        except Exception:
            logger.exception("获取ECH密钥失败，域名: {}", domain)
            return None

    @cached(ECH_CACHE.get, key=_ech_cache_key, lock=ECH_CACHE.lock)
    async def _resolve_ech(self, domain: str | Name) -> ECHResult:
        if isinstance(domain, str):
            domain = from_text(domain)
        assert self.resolver is not None
        ans = await self.resolver.resolve(domain, RdataType.HTTPS)
        expiration = min(ans.expiration, time() + 300)
        if ans.rrset is not None:
            for rr in ans.rrset:
                if rr.priority == 0:
                    continue
                ecl = rr.params.get(ParamKey.ECH)
                if ecl is not None:
                    return ECHResult(ecl.to_text().strip('"'), expiration)
        return ECHResult(None, expiration)
