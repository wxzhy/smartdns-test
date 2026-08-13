from typing import TYPE_CHECKING

from anyio import CancelScope
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
    def __init__(self, config: list[NameserverConfig], client: HTTPClient) -> None:
        self.config = config
        self.nameservers: dict[str, BaseNameserver] = {}
        self._client = client

    async def start_all(self) -> None:
        try:
            for config in self.config:
                match config:
                    case TCPNameserverConfig():
                        nameserver: BaseNameserver = TCPNameserver(config=config)
                    case UDPNameserverConfig():
                        nameserver = UDPNameserver(config=config)
                    case CurlNameserverConfig():
                        nameserver = CurlNameserver(config=config, client=self._client)
                    case _:
                        raise ValueError(f"不支持的上游类型: {config.type}")
                self.nameservers[nameserver.name] = nameserver
                await nameserver.start()
        except BaseException:
            with CancelScope(shield=True):
                await self.stop_all()
            raise

    def get(self, name: str) -> BaseNameserver | None:
        return self.nameservers.get(name)

    async def stop_all(self) -> None:
        nameservers = list(self.nameservers.values())
        self.nameservers.clear()
        for nameserver in reversed(nameservers):
            try:
                await nameserver.stop()
            except Exception:
                logger.exception("停止 Nameserver {} 失败", nameserver.name)
