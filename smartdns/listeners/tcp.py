from __future__ import annotations

from time import time
from typing import TYPE_CHECKING, cast

from anyio import (
    ClosedResourceError,
    Semaphore,
    create_task_group,
    create_tcp_listener,
    fail_after,
)
from dns.asyncquery import receive_tcp, send_tcp
from loguru import logger

from smartdns.listeners._socket import AnyioStreamSocket
from smartdns.listeners.base import BaseListener
from smartdns.models.context import Request

if TYPE_CHECKING:
    from collections.abc import Sequence

    from anyio.abc import SocketListener, SocketStream
    from anyio.streams.stapled import MultiListener
    from dns.message import Message

    from smartdns.listeners.base import Handler
    from smartdns.models.listener import Do53ListenerConfig


class TCPListener(BaseListener):
    """TCP监听器类"""

    def __init__(self, config: Do53ListenerConfig, max_connections: int = 256):
        super().__init__(config)
        self.host = config.host
        self.port = config.port
        self.reuse_port = config.reuse_port
        self._max_connections = max_connections
        self._listener: MultiListener[SocketStream] | None = None

    @staticmethod
    def _serialize_response(response: Message) -> bytes:
        """序列化完整 TCP DNS 响应，不继承 UDP EDNS payload 限制。"""
        return response.to_wire(max_size=65535)

    async def start(self, handler: Handler):
        """启动TCP监听器并进入接收循环。"""
        self._listener = await create_tcp_listener(
            local_host=self.host, local_port=self.port, reuse_port=self.reuse_port
        )
        self.handler = handler
        logger.info(f"TCP监听器 {self.name} 已启动，监听地址: {self.host}:{self.port}")
        limiter = Semaphore(self._max_connections)
        listener = self._listener
        assert listener is not None
        # anyio 返回的 MultiListener 没有 accept()，需要为每个底层监听器启动接收循环。
        listeners = cast("Sequence[SocketListener]", listener.listeners)

        async def accept_connections(socket_listener: SocketListener) -> None:
            while True:
                try:
                    stream = await socket_listener.accept()
                except ClosedResourceError:
                    return
                except Exception:
                    logger.warning("TCP监听器 {} 接收连接失败", self.name)
                    continue
                await limiter.acquire()
                try:
                    tg.start_soon(self._handle_connection, stream, limiter)
                except BaseException:
                    limiter.release()
                    raise

        async with listener, create_task_group() as tg:
            for socket_listener in listeners:
                tg.start_soon(accept_connections, socket_listener)

    async def _handle_connection(self, stream: SocketStream, limiter: Semaphore):
        """处理单个连接；连接任务结束后释放并发额度。"""
        try:
            await self.handle_connection(stream)
        finally:
            limiter.release()

    async def stop(self):
        """停止TCP监听器"""
        if self._listener is not None:
            await self._listener.aclose()
            self._listener = None
            logger.info(f"TCP监听器 {self.name} 已停止")

    async def handle_connection(self, stream: SocketStream):
        """处理传入的TCP连接"""
        handler = self.handler
        if handler is None:
            return
        async with stream:
            anyio_stream = AnyioStreamSocket(stream)
            peer = await anyio_stream.getpeername()
            client_address = peer[0] if peer is not None else None
            logger.debug(f"接收到来自 {client_address} 的TCP连接")
            try:
                while True:
                    # 等待客户端下一个查询的空闲超时。
                    with fail_after(self.timeout):
                        data, _ = await receive_tcp(anyio_stream, ignore_trailing=True)
                    if not data.question:
                        logger.debug("TCP监听器 {} 跳过无 question 报文", self.name)
                        continue
                    # 与 UDP 监听器对齐：构造请求、处理与回写共享同一处理超时。
                    with fail_after(self.timeout):
                        request = Request.from_message(
                            msg=data,
                            listener=self.name,
                            remote_address=client_address,
                        )
                        response: Message | None = await handler(request)
                        if response is not None:
                            wire = self._serialize_response(response)
                            await send_tcp(
                                anyio_stream,
                                wire,
                                expiration=time() + self.timeout,
                            )
            except EOFError:
                # 客户端正常关闭连接（读到 EOF），非错误路径。
                pass
            except TimeoutError:
                logger.warning(f"TCP监听器 {self.name} 请求处理超时")
            except Exception as error:
                logger.warning(
                    "TCP监听器 {} 处理连接失败: {}: {}",
                    self.name,
                    type(error).__name__,
                    error,
                )
