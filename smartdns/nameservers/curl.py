"""DNS over HTTPS 上游（curl-cffi，支持 ECH 与浏览器指纹模拟）。"""

from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.flags
import dns.message
from anyio import fail_after
from curl_cffi import AsyncSession, CurlOpt
from dns.query import BadResponse
from dns.rdatatype import RdataType
from loguru import logger

from smartdns.nameservers.base import (
    BaseNameserver,
    query_deadline,
    remaining_timeout,
)

if TYPE_CHECKING:
    from smartdns.models.nameserver import CurlNameserverConfig
    from smartdns.nameservers.client import HTTPClient


class CurlNameserver(BaseNameserver):
    def __init__(self, config: CurlNameserverConfig, client: HTTPClient):
        super().__init__(config)
        self.url = str(config.url)
        self.host: str | None = (
            config.host if config.host is not None else config.url.host
        )
        self.port: int | None = config.url.port
        self.want_get = config.want_get
        self.ech = config.ech
        self.verify = config.verify
        self.fingerprint = config.fingerprint
        self._curl: AsyncSession | None = None
        self._client = client

    async def start(self):
        """启动Curl解析器，创建本上游独占的 HTTP 会话。"""
        options: dict[CurlOpt, object] | None = (
            {CurlOpt.ECH: "true"} if self.ech is True else None
        )
        # hosts 映射按本上游 URL 的端口生成 RESOLVE 条目（默认 https 已规范化为 443）。
        resolve = self._client.resolve_entries(self.port) if self.port else []
        if resolve:
            options = {**(options or {}), CurlOpt.RESOLVE: resolve}
        self._curl = self._client.create_session(options, impersonate=self.fingerprint)
        logger.info(
            "Curl解析器 {} 已启动，目标: {}, Host: {}, want_get: {}, ech: {}, "
            "fingerprint: {}",
            self.name,
            self.url,
            self.host,
            self.want_get,
            self.ech,
            self.fingerprint,
        )

    async def stop(self):
        """停止Curl解析器，关闭独占的 HTTP 会话。"""
        if self._curl is not None:
            await self._curl.close()
            self._curl = None

    def kind(self):
        return "curl"

    def is_always_max_size(self) -> bool:
        return True

    def answer_nameserver(self) -> str:
        assert self.host is not None
        return self.host

    def answer_port(self) -> int:
        assert self.port is not None
        return self.port

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        if self._curl is None:
            raise ValueError("Curl解析器未启动")
        deadline = query_deadline(timeout, self.timeout)
        message = request.to_wire()
        encoded = urlsafe_b64encode(message).decode("ascii").rstrip("=")
        if isinstance(self.ech, str):
            # 本会话为此上游独占、ECH 域名固定，故设置在会话级安全无竞态。
            # 超时包在缓存等待者外层：并发调用即使共享同一底层 ECH 查询，
            # 每个 DNS 请求仍遵守自己的剩余 lifetime。
            with fail_after(remaining_timeout(deadline)):
                ech_key = await self._client.get_ech_key(self.ech)
            if ech_key is not None:
                self._curl.curl_options[CurlOpt.ECH] = f"ecl:{ech_key}"
                # ECH 密钥属于敏感数据，日志只记录已配置状态，不打印密钥内容。
                logger.debug("Curl 上游 {} 已设置 ECH 密钥", self.name)
            else:
                self._curl.curl_options.pop(CurlOpt.ECH, None)
                logger.warning(
                    "Curl 上游 {} 未能获取 ECH 密钥，使用默认设置", self.name
                )
        try:
            # curl 的 timeout 从取到句柄后才计时，外层范围还须覆盖会话池排队。
            with fail_after(remaining_timeout(deadline)):
                if self.want_get:
                    result = await self._curl.get(
                        self.url,
                        params={"dns": encoded},
                        headers={
                            "Host": self.host,
                            "Accept": "application/dns-message",
                        },
                        timeout=remaining_timeout(deadline),
                        verify=self.verify,
                    )
                else:
                    result = await self._curl.post(
                        self.url,
                        data=message,
                        headers={
                            "Host": self.host,
                            "Content-Type": "application/dns-message",
                            "Accept": "application/dns-message",
                        },
                        timeout=remaining_timeout(deadline),
                        verify=self.verify,
                    )
        except Exception as error:
            logger.warning(
                "Curl 上游 {} 请求失败: {}: {}", self.name, type(error).__name__, error
            )
            raise
        if result.status_code != 200:
            raise ValueError(
                f"Curl解析器 {self.name} 返回非200状态码: {result.status_code}"
            )
        response = dns.message.from_wire(
            result.content,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )
        # DoH 通过 HTTP 关联请求，DNS ID 可不同；Question 与消息语义仍须校验。
        if (
            not response.flags & dns.flags.QR
            or response.flags & dns.flags.TC
            or response.opcode() != request.opcode()
            or response.question != request.question
        ):
            raise BadResponse
        age_text = result.headers.get("Age", "0").strip()
        age = 0
        if age_text.isascii() and age_text.isdigit():
            digits = age_text.lstrip("0") or "0"
            # 超大 Age 只需使全部 DNS TTL 归零，避免无界整数转换。
            age = int(digits) if len(digits) <= 10 else 0xFFFFFFFF
        if age:
            for section in response.sections[1:]:
                for rrset in section:
                    ttl = rrset.ttl
                    # 负缓存的寿命还受 SOA.minimum 限制，必须一起扣除 HTTP Age。
                    if rrset.rdtype == RdataType.SOA:
                        ttl = min(ttl, *(rr.minimum for rr in rrset))
                    rrset.ttl = max(0, ttl - age)
        # 关闭 RRset 索引以释放缓存响应中多余的引用（dnspython 运行期支持 index=None，
        # 但其类型标注未含 None）。
        response.index = None  # ty: ignore[invalid-assignment]
        return response
