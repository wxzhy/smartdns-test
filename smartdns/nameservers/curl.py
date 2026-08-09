from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.message
from curl_cffi import AsyncSession, CurlOpt
from loguru import logger

from smartdns.nameservers.base import BaseNameserver

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
        self._curl: AsyncSession | None = None
        self._client = client

    async def start(self):
        """启动Curl解析器，创建本上游独占的 HTTP 会话。"""
        self._curl = self._client.create_session()
        logger.info(
            f"Curl解析器 {self.name} 已启动，目标: {self.url}, Host: {self.host}, "
            f"want_get: {self.want_get}, ech: {self.ech}"
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
        message = request.to_wire()
        encoded = urlsafe_b64encode(message).decode("ascii").rstrip("=")
        if isinstance(self.ech, str):
            # 本会话为此上游独占、ECH 域名固定，故设置在会话级安全无竞态。
            ech_key = await self._client.get_ech_key(self.ech)
            if ech_key is not None:
                self._curl.curl_options[CurlOpt.ECH] = f"ecl:{ech_key.strip(r'"')}"
            else:
                logger.warning(f"Curl解析器 {self.name} 未能获取ECH密钥，使用默认设置")
        try:
            if self.want_get:
                result = await self._curl.get(
                    self.url,
                    params={"dns": encoded},
                    headers={"Host": self.host, "Accept": "application/dns-message"},
                    timeout=int(timeout),
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
                    timeout=int(timeout),
                    verify=self.verify,
                )
        except Exception:
            logger.exception(f"Curl解析器 {self.name} 请求失败")
            raise
        if result.status_code != 200:
            raise ValueError(
                f"Curl解析器 {self.name} 返回非200状态码: {result.status_code}"
            )
        response = dns.message.from_wire(result.content)
        # 关闭 RRset 索引以释放缓存响应中多余的引用（dnspython 运行期支持 index=None，
        # 但其类型标注未含 None）。
        response.index = None  # ty: ignore[invalid-assignment]
        return response
