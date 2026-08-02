from base64 import urlsafe_b64encode

import dns.message
from curl_cffi import AsyncSession, CurlOpt
from dns.name import from_text
from loguru import logger

from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.base import BaseNameserver
from smartdns.nameservers.client import HTTPClient


class CurlNameserver(BaseNameserver):
    def __init__(self, config: CurlNameserverConfig, client: HTTPClient):
        super().__init__(config)
        self.url = str(config.url)
        self.host: str | None = (
            str(config.host) if config.host is not None else config.url.host
        )
        self.port: int | None = config.url.port
        self.want_get = config.want_get
        self.ech = config.ech
        self.verify = config.verify
        self._curl: AsyncSession | None = None
        self._client = client

    async def start(self):
        """启动Curl解析器"""
        self._curl = self._client.get_curl()
        logger.info(
            f"Curl解析器 {self.name} 已启动，目标地址: {self.url}, Host: {self.host}, want_get: {self.want_get}, ech: {self.ech}"
        )

    def kind(self):
        return "curl"

    def answer_nameserver(self) -> str:
        return self.host

    def answer_port(self) -> int:
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
        try:
            if isinstance(self.ech, str):
                # 读取echconfiglist
                ech_key = await self._client.get_ech_key(from_text(self.ech))
                if ech_key is not None:
                    logger.debug(f"Curl解析器 {self.name} 获取ECH密钥: {ech_key}")
                    self._curl.curl_options[CurlOpt.ECH] = f"ecl:{ech_key.strip(r'"')}"
                    logger.debug(f"当前curl选项: {self._curl.curl_options}")
                else:
                    logger.warning(
                        f"Curl解析器 {self.name} 未能获取ECH密钥，继续使用默认设置"
                    )
            if self.want_get:
                result = await self._curl.get(
                    self.url,
                    params={"dns": encoded},
                    headers={"Host": self.host},
                    timeout=int(timeout),
                    verify=self.verify,
                )
            else:
                result = await self._curl.post(
                    str(self.url),
                    data=message,
                    headers={"Host": self.host},
                    timeout=int(timeout),
                    verify=self.verify,
                )
            if result.status_code != 200:
                raise ValueError(
                    f"Curl解析器 {self.name} 返回非200状态码: {result.status_code}"
                )
            response = dns.message.from_wire(result.content)
            return response
        except Exception as e:
            logger.exception(f"Curl解析器 {self.name} 查询失败: {e}")
            raise
