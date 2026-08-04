from typing import TYPE_CHECKING

from loguru import logger

from smartdns.models.nameserver import (
    CurlNameserverConfig,
    NameserverConfig,
    TCPNameserverConfig,
    UDPNameserverConfig,
)
from smartdns.nameservers.curl import CurlNameserver
from smartdns.nameservers.tcp import TCPNameserver
from smartdns.nameservers.udp import UDPNameserver

if TYPE_CHECKING:
    from smartdns.nameservers.base import BaseNameserver
    from smartdns.nameservers.client import HTTPClient


class NameserverManager:
    def __init__(self, config: list[NameserverConfig], client: HTTPClient):
        self.config = config
        self.nameservers: dict[str, BaseNameserver] = {}
        self._client = client

    async def start_all(self) -> None:
        for nameserver_config in self.config:
            match nameserver_config:
                case TCPNameserverConfig():
                    logger.info(
                        f"创建TCP上游: {nameserver_config.name}，"
                        f"地址: {nameserver_config.address}:{nameserver_config.port}"
                    )
                    nameserver: BaseNameserver = TCPNameserver(config=nameserver_config)
                case UDPNameserverConfig():
                    logger.info(
                        f"创建UDP上游: {nameserver_config.name}，"
                        f"地址: {nameserver_config.address}:{nameserver_config.port}"
                    )
                    nameserver = UDPNameserver(config=nameserver_config)
                case CurlNameserverConfig():
                    logger.info(
                        f"创建Curl上游: {nameserver_config.name}，"
                        f"地址: {nameserver_config.url}"
                    )
                    nameserver = CurlNameserver(
                        config=nameserver_config, client=self._client
                    )
                case _:
                    raise ValueError(f"不支持的上游类型: {nameserver_config.type}")
            await nameserver.start()
            self.nameservers[nameserver.name] = nameserver

    def get(self, name: str) -> BaseNameserver | None:
        return self.nameservers.get(name)

    async def stop_all(self) -> None:
        for nameserver in self.nameservers.values():
            await nameserver.stop()
