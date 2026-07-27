from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartdns.models.listener import ListenerConfig


class BaseListener:
    def __init__(self, config: ListenerConfig):
        self.config = config
        self.name = config.name

    async def start(self, handler):
        raise NotImplementedError("start method must be implemented by subclasses")

    async def stop(self):
        raise NotImplementedError("stop method must be implemented by subclasses")
