from time import time
from typing import TYPE_CHECKING

from anyio import create_tcp_listener
from dns.asyncquery import receive_tcp, send_tcp
from loguru import logger

from smartdns.listeners._socket import AnyioStreamSocket
from smartdns.listeners.base import BaseListener
from smartdns.models.context import Request

if TYPE_CHECKING:
    from anyio.abc import SocketStream
    from dns.message import Message

    from smartdns.listeners.base import Handler
    from smartdns.models.listener import Do53ListenerConfig


class TCPListener(BaseListener):
    """TCP监听器类"""

    def __init__(self, config: Do53ListenerConfig):
        super().__init__(config)
        self.host = config.host
        self.port = config.port
        self.reuse_port = config.reuse_port
        self._listener = None

    async def start(self, handler: Handler):
        """启动TCP监听器"""
        self._listener = await create_tcp_listener(
            local_host=self.host, local_port=self.port, reuse_port=self.reuse_port
        )
        self.handler = handler
        logger.info(f"TCP监听器 {self.name} 已启动，监听地址: {self.host}:{self.port}")
        async with self._listener:
            await self._listener.serve(self.handle_connection)

    async def stop(self):
        """停止TCP监听器"""
        if self._listener is not None:
            await self._listener.aclose()
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
                    data, _ = await receive_tcp(anyio_stream, ignore_trailing=True)
                    request = Request.from_message(
                        msg=data, listener=self.name, remote_address=client_address
                    )
                    response: Message | None = await handler(request)
                    if response is not None:
                        await send_tcp(
                            anyio_stream,
                            response.to_wire(),
                            expiration=time() + self.timeout,
                        )
            except EOFError:
                # 客户端正常关闭连接（读到 EOF），非错误路径。
                pass
            except Exception:
                logger.warning(f"TCP监听器 {self.name} 处理连接失败")
