"""监听器基类与入站报文筛查。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from ipaddress import ip_address
from typing import TYPE_CHECKING

from dns.flags import QR
from dns.opcode import Opcode
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Request, reply_to

if TYPE_CHECKING:
    from dns.message import Message

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
    response = reply_to(msg)
    response.set_rcode(Rcode.NOTIMP)
    return response


class BaseListener:
    """UDP/TCP 监听器的公共部分：请求处理与失败日志。"""

    # 日志中的传输协议名称。
    transport = "DNS"

    def __init__(self, config: ListenerConfig):
        self.config = config
        self.name = config.name
        self.timeout = config.timeout
        self.handler: Handler | None = None

    async def start(self, handler: Handler) -> None:
        raise NotImplementedError("start method must be implemented by subclasses")

    async def stop(self) -> None:
        raise NotImplementedError("stop method must be implemented by subclasses")

    async def answer(
        self, msg: Message, remote_address: str | None, deadline: float
    ) -> Message | None:
        """筛查操作码、构造 Request 并交给处理器；返回 None 表示不应答。"""
        response = unsupported_opcode_response(msg)
        if response is not None:
            logger.debug(
                "{} 监听器 {} 拒绝操作码 {}",
                self.transport,
                self.name,
                msg.opcode().name,
            )
            return response
        assert self.handler is not None
        request = Request.from_message(
            msg=msg,
            listener=self.name,
            remote_address=ip_address(remote_address) if remote_address else None,
            deadline=deadline,
        )
        return await self.handler(request)

    @contextmanager
    def log_failures(self) -> Iterator[None]:
        """单个请求的超时与异常只记录日志，不影响监听器继续服务。"""
        try:
            yield
        except TimeoutError:
            logger.warning("{} 监听器 {} 请求处理超时", self.transport, self.name)
        except Exception as error:
            # 不用 logger.exception：Loguru diagnose 会展开局部变量，从而把
            # 完整 DNS wire 写入日志。
            logger.warning(
                "{} 监听器 {} 处理请求失败: {}: {}",
                self.transport,
                self.name,
                type(error).__name__,
                error,
            )
