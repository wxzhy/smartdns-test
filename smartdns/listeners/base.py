from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from dns.flags import QR
from dns.message import make_response
from dns.opcode import Opcode
from dns.rcode import Rcode

if TYPE_CHECKING:
    from dns.message import Message

    from smartdns.models.context import Request
    from smartdns.models.listener import ListenerConfig

# 监听器接收到请求后调用的处理器：Request -> Message | None（None 表示不应答）。
Handler = Callable[["Request"], Awaitable["Message | None"]]


def should_drop(msg: Message) -> bool:
    """应答报文（QR=1）与无 question 的报文直接丢弃。

    回应应答报文会让两个转发器互相把对方的应答当查询，形成环路。
    """
    return bool(msg.flags & QR) or not msg.question


def unsupported_opcode_response(msg: Message) -> Message | None:
    """非 QUERY 操作码（NOTIFY/UPDATE 等）返回 NOTIMP，不进入解析流程。"""
    if msg.opcode() == Opcode.QUERY:
        return None
    response = make_response(msg, True, our_payload=1232, pad=0)
    response.set_rcode(Rcode.NOTIMP)
    return response


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
