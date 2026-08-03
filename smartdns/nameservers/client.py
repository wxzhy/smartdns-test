from ipaddress import IPv6Address
from threading import Lock
from typing import ClassVar

from cachetools import TTLCache
from curl_cffi import AsyncSession, CurlHttpVersion, CurlOpt
from dns.name import Name, from_text
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from loguru import logger

from smartdns.models.config import HTTPClientConfig
from smartdns.resolvers.aiodns import AioDNSResolver
from smartdns.utils.cache_async import cached


class HTTPClient:
    cache: ClassVar[TTLCache] = TTLCache(maxsize=10, ttl=300)

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
        logger.info("启动HTTP客户端")
        if self.resolver is not None:
            await self.resolver.start()

    def _base_curl_options(self) -> dict[CurlOpt, object]:
        """根据客户端配置构建基础 curl 选项（DOH / 静态 hosts / DNS 缓存 / ECH）。"""
        opt: dict[CurlOpt, object] = {}
        if self.config.doh is not None:
            opt[CurlOpt.DOH_URL] = str(self.config.doh)
            opt[CurlOpt.DOH_SSL_VERIFYPEER] = (
                "true" if self.config.doh_verify else "false"
            )
        if self.config.hosts is not None:
            resolve = []
            for host, ips in self.config.hosts.items():
                for ip in ips:
                    if isinstance(ip, IPv6Address):
                        resolve.append(f"{host}:443:[{ip}]")
                    else:
                        resolve.append(f"{host}:443:{ip}")
            opt[CurlOpt.RESOLVE] = resolve
        opt[CurlOpt.DNS_CACHE_TIMEOUT] = self.config.dns_cache_ttl
        opt[CurlOpt.DNS_SHUFFLE_ADDRESSES] = 1 if self.config.shuffle else 0
        opt[CurlOpt.ECH] = "true"
        return opt

    def create_session(
        self, extra_options: dict[CurlOpt, object] | None = None
    ) -> AsyncSession:
        """创建一个独立的 AsyncSession。

        每个 CurlNameserver 各持一个，避免共享会话被逐请求修改 curl_options[ECH]
        导致的并发竞态与跨上游污染。
        """
        opt = self._base_curl_options()
        if extra_options:
            opt.update(extra_options)
        return AsyncSession(
            headers={"Accept": "application/dns-message"},
            max_clients=self.config.max_clients,
            http_version=CurlHttpVersion.V2TLS,
            default_headers=True,
            impersonate="chrome",
            curl_options=opt,
        )

    @cached(cache, key=lambda self, domain: (id(self), str(domain)), lock=Lock())
    async def get_ech_key(self, domain: str | Name) -> str | None:
        if self.resolver is None:
            raise ValueError("HTTP客户端未配置上游DNS解析器")
        if isinstance(domain, str):
            domain = from_text(domain)
        try:
            ans = await self.resolver.resolve(domain, RdataType.HTTPS)
            if ans.rrset is not None:
                for rr in ans.rrset:
                    ecl = rr.params.get(ParamKey.ECH)
                    if ecl is not None:
                        return ecl.to_text()
        except Exception:
            logger.exception("获取ECH密钥失败，域名: {}", domain)
        return None
