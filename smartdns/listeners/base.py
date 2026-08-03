from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dns.message import Message

    from smartdns.models.context import Request
    from smartdns.models.listener import ListenerConfig

# 监听器接收到请求后调用的处理器：Request -> Message | None（None 表示不应答）。
Handler = Callable[["Request"], Awaitable["Message | None"]]


class BaseListener:
    def __init__(self, config: ListenerConfig):
        self.config = config
        self.name = config.name
        self.timeout = config.timeout
        self.handler: Handler | None = None

    async def start(self, handler: Handler) -> None:
        raise NotImplementedError("start method must be implemented by subclasses")

    async def stop(self) -> None:
        raise NotImplementedError("stop method must be implemented by subclasses")
