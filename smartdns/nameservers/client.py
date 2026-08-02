from ipaddress import IPv6Address
from typing import ClassVar

from cachetools import TTLCache
from cachetools_async import cached
from curl_cffi import AsyncSession, CurlHttpVersion, CurlOpt
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from loguru import logger

from smartdns.models.config import HTTPClientConfig
from smartdns.resolvers.aiodns import AioDNSResolver


class HTTPClient:
    cache: ClassVar[TTLCache] = TTLCache(maxsize=10, ttl=300)

    def __init__(self, config: HTTPClientConfig):
        self.config = config
        self.resolver: AioDNSResolver | None = (
            AioDNSResolver(config=config.resolver)
            if config.resolver is not None
            else None
        )
        self.curl: AsyncSession | None = None

    async def start(self):
        """启动HTTP客户端"""
        logger.info("启动HTTP客户端")
        if self.resolver is not None:
            await self.resolver.start()
            logger.debug(f"HTTP客户端使用的上游DNS解析器: {self.resolver.name}")
        opt: dict[CurlOpt, object] = {}
        if self.config.doh is not None:
            opt[CurlOpt.DOH_URL] = str(self.config.doh)
            opt[CurlOpt.DOH_SSL_VERIFYPEER] = (
                "true" if self.config.doh_verify else "false"
            )
        if self.config.hosts is not None:
            resolve = []
            for host, ip in self.config.hosts:
                if isinstance(ip, IPv6Address):
                    resolve.append(f"{host}:443:[{ip}]")
                else:
                    resolve.append(f"{host}:443:{ip}")
            opt[CurlOpt.RESOLVE] = resolve
        opt[CurlOpt.DNS_CACHE_TIMEOUT] = self.config.dns_cache_ttl
        opt[CurlOpt.DNS_SHUFFLE_ADDRESSES] = 1 if self.config.shuffle else 0
        opt[CurlOpt.ECH] = "true"
        self.curl = AsyncSession(
            headers={"Accept": "application/dns-message"},
            max_clients=self.config.max_clients,
            http_version=CurlHttpVersion.V2TLS,
            default_headers=True,
            impersonate="chrome",
            curl_options=opt,
        )

    @cached(cache, key=lambda self, domain: domain)
    async def get_ech_key(self, domain):
        if self.resolver is None:
            raise ValueError("HTTP客户端未配置上游DNS解析器")
        try:
            ans = await self.resolver.resolve(domain, RdataType.HTTPS)
            if ans.rrset is not None:
                for rr in ans.rrset:
                    ecl = rr.params.get(ParamKey.ECH)
                    if ecl is not None:
                        return ecl
        except Exception as e:
            logger.exception(f"获取ECH密钥时发生错误: {e}")
        return None

    def get_curl(self) -> AsyncSession:
        if self.curl is None:
            raise ValueError("HTTP客户端未启动")
        return self.curl
