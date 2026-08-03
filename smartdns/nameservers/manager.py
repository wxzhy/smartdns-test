from typing import TYPE_CHECKING

from loguru import logger

from smartdns.models.nameserver import NameserverConfig
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.curl import CurlNameserver
from smartdns.nameservers.tcp import TCPNameserver
from smartdns.nameservers.udp import UDPNameserver

if TYPE_CHECKING:
    from smartdns.nameservers.base import BaseNameserver


class NameserverManager:
    def __init__(self, config: list[NameserverConfig], client: HTTPClient):
        self.config = config
        self.http_client_config = client
        logger.debug(self.config)
        self.nameservers: dict[str, BaseNameserver] = {}
        self._client = client

    async def start_all(self):
        for nameserver_config in self.config:
            match nameserver_config.type:
                case "tcp":
                    logger.info(
                        f"创建TCP监听器: {nameserver_config.name}，地址: {nameserver_config.address}:{nameserver_config.port}"
                    )
                    nameserver = TCPNameserver(config=nameserver_config)
                case "udp":
                    logger.info(
                        f"创建UDP监听器: {nameserver_config.name}，地址: {nameserver_config.address}:{nameserver_config.port}"
                    )
                    nameserver = UDPNameserver(config=nameserver_config)
                case "curl":
                    logger.info(
                        f"创建Curl监听器: {nameserver_config.name}，地址: {nameserver_config.url}"
                    )
                    nameserver = CurlNameserver(
                        config=nameserver_config, client=self._client
                    )
                case _:
                    raise ValueError(f"不支持的监听器类型: {nameserver_config.type}")
            await nameserver.start()
            self.nameservers[nameserver.name] = nameserver

    def get(self, name: str) -> BaseNameserver | None:
        return self.nameservers.get(name, None)

    async def stop_all(self):
        for nameserver in self.nameservers.values():
            await nameserver.stop()
