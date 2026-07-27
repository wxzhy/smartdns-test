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


class TCPListener(BaseListener):
    """TCP监听器类"""

    def __init__(self, config: Do53Listener):
        super().__init__(config)
        self.host = config.host
        self.port = config.port
        self.reuse_port = config.reuse_port
        self.timeout = config.timeout
        self._listener = None

    async def start(self, handler):
        """启动TCP监听器"""
        self._listener = await create_tcp_listener(
            local_host=self.host, local_port=self.port, reuse_port=self.reuse_port
        )
        self.handler = handler
        logger.info(f"TCP监听器 {self.name} 已启动，监听地址: {self.host}:{self.port}")
        async with self._listener:
            await self._listener.serve(self.handle_connection)

    async def handle_connection(self, stream: SocketStream):
        """处理传入的TCP连接"""

        # 转换为AnyioStreamSocket对象
        anyio_stream = AnyioStreamSocket(stream)
        client_address, client_port = await anyio_stream.getpeername()
        logger.debug(f"接收到来自 {client_address}:{client_port} 的TCP连接")
        # 在这里实现对传入连接的处理逻辑
        # 例如读取数据、解析请求、发送响应等
        try:
            while True:
                data, receive_time = await receive_tcp(
                    anyio_stream, ignore_trailing=True
                )
                logger.debug(f"在 {receive_time} 接收到数据: {data}")
                # 处理数据并发送响应
                request = Request.from_message(
                    msg=data, listener=self.name, remote_address=client_address
                )
                response: Message | None = await self.handler(request)
                if response is not None:
                    await send_tcp(
                        anyio_stream,
                        response.to_wire(),
                        expiration=time() + self.timeout,
                    )
        except Exception as e:
            logger.error(f"处理连接时发生错误: {e}")
        finally:
            await stream.aclose()
            logger.info(f"关闭来自 {client_address} 的TCP连接")
