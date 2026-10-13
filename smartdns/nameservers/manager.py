"""按配置创建并管理单个 Worker 内的全部上游 Nameserver。"""

from typing import TYPE_CHECKING

from smartdns.models.nameserver import (
    CurlNameserverConfig,
    NameserverConfig,
    TCPNameserverConfig,
    TLSNameserverConfig,
    UDPNameserverConfig,
)
from smartdns.nameservers.curl import CurlNameserver
from smartdns.nameservers.tcp import TCPNameserver
from smartdns.nameservers.tls import TLSNameserver
from smartdns.nameservers.udp import UDPNameserver
from smartdns.utils.components import ComponentManager

if TYPE_CHECKING:
    from smartdns.nameservers.base import BaseNameserver
    from smartdns.nameservers.client import HTTPClient


class NameserverManager(ComponentManager[NameserverConfig, "BaseNameserver"]):
    kind = "Nameserver"

    def __init__(self, config: list[NameserverConfig], client: HTTPClient) -> None:
        super().__init__(config)
        self._client = client

    @property
    def nameservers(self) -> dict[str, BaseNameserver]:
        return self.components

    def _create(self, config: NameserverConfig) -> BaseNameserver:
        match config:
            case TCPNameserverConfig():
                return TCPNameserver(config=config)
            case TLSNameserverConfig():
                return TLSNameserver(config=config)
            case UDPNameserverConfig():
                return UDPNameserver(config=config)
            case CurlNameserverConfig():
                return CurlNameserver(config=config, client=self._client)
            case _:
                raise ValueError(f"不支持的上游类型: {config.type}")

    async def start_all(self) -> None:
        await self._start_components()
