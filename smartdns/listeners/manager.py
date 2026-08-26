from typing import TYPE_CHECKING

from anyio import CancelScope, create_task_group
from loguru import logger

from smartdns.listeners.tcp import TCPListener
from smartdns.listeners.udp import UDPListener

if TYPE_CHECKING:
    from smartdns.listeners.base import BaseListener
    from smartdns.models.listener import ListenerConfig


class ListenerManager:
    def __init__(self, config: list[ListenerConfig]):
        self.config = config
        self.listeners: list[BaseListener] = []

    async def start_all(self, handler):
        try:
            async with create_task_group() as tg:
                for listener_config in self.config:
                    match listener_config.type:
                        case "tcp":
                            logger.info("创建TCP监听器: {}", listener_config.name)
                            listener = TCPListener(config=listener_config)
                        case "udp":
                            logger.info("创建UDP监听器: {}", listener_config.name)
                            listener = UDPListener(config=listener_config)
                        case _:
                            raise ValueError(
                                f"不支持的监听器类型: {listener_config.type}"
                            )
                    self.listeners.append(listener)
                    tg.start_soon(listener.start, handler)
        except BaseException:
            with CancelScope(shield=True):
                await self.stop_all()
            raise

    async def stop_all(self):
        listeners = list(self.listeners)
        self.listeners.clear()
        for listener in reversed(listeners):
            try:
                await listener.stop()
            except Exception:
                logger.exception("停止监听器 {} 失败", listener.name)
