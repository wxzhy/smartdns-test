from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from smartdns.listeners.base import BaseListener


class NameserverManager:
    def __init__(self, config: list[ListenerConfig]):
        self.config = config
        logger.debug(self.config)
        self.nameservers: dict[str, BaseListener] = {}

    async def start_all(self, handler):
        for nameserver_config in self.config:
            match nameserver_config.type:
                case "tcp":
                    logger.info(
                        f"创建TCP监听器: {nameserver_config.name}，地址: {nameserver_config.host}:{nameserver_config.port}"
                    )
                    nameserver = TCPNameserver(config=nameserver_config)
                case "udp":
                    logger.info(
                        f"创建UDP监听器: {nameserver_config.name}，地址: {nameserver_config.host}:{nameserver_config.port}"
                    )
                    nameserver = UDPNameserver(config=nameserver_config)
                case _:
                    raise ValueError(f"不支持的监听器类型: {nameserver_config.type}")
            await nameserver.start(handler)
            self.nameservers[nameserver_config.name] = nameserver

    async def stop_all(self):
        for nameserver in self.nameservers.values():
            await nameserver.stop()
