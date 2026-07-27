from socket import (
    AF_INET6,
    IPPROTO_IPV6,
    IPV6_V6ONLY,
    SO_EXCLUSIVEADDRUSE,
    SO_REUSEADDR,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)
from sys import platform
from time import time
from typing import TYPE_CHECKING

from anyio.abc import UDPSocket
from dns.asyncquery import receive_udp, send_udp
from dns.inet import af_for_address
from loguru import logger

from smartdns.listeners._socket import AnyioDatagramSocket
from smartdns.listeners.base import BaseListener
from smartdns.models.context import Request

if TYPE_CHECKING:
    from smartdns.models.listener import Do53ListenerConfig
if platform != "win32":
    from socket import SO_REUSEPORT


class UDPListener(BaseListener):
    def __init__(self, config: Do53ListenerConfig):
        super().__init__(config)
        self.host = str(config.host) if config.host is not None else "::"
        logger.debug(f"UDP监听器 {self.name} 使用的监听地址: {self.host}")
        self.port = config.port
        self.reuse_port = config.reuse_port
        self.timeout = config.timeout
        self._listener = None
        self._family = af_for_address(self.host) if self.host else AF_INET6
        self._sock = socket(self._family, SOCK_DGRAM)
        # 允许同时接收IPv4和IPv6数据包
        self._sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
        # 设置为非阻塞模式
        self._sock.setblocking(False)
        # 在Windows上使用SO_EXCLUSIVEADDRUSE来确保端口独占
        if platform == "win32":
            self._sock.setsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
        else:
            # 允许地址重用
            self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            if self.reuse_port:
                self._sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        self._sock.bind((self.host, self.port))

    async def start(self, handler):
        """启动UDP监听器"""
        # self._listener = await create_udp_socket(
        #     local_host=self.host, local_port=self.port, reuse_port=self.reuse_port
        # )
        # Anyio的create_udp_socket在某些平台上可能不支持同时启用ipv4/ipv6，因此使用低级API创建UDP套接字
        self._listener = await UDPSocket.from_socket(self._sock)
        logger.info(f"UDP监听器 {self.name} 已启动，监听地址: {self.host}:{self.port}")
        self.handler = handler
        anyio_socket = AnyioDatagramSocket(self._listener)
        try:
            while True:
                data, receive_time, client = await receive_udp(
                    anyio_socket, ignore_trailing=True
                )
                client_address, client_port = client
                logger.debug(
                    f"在{receive_time} 收到来自 {client_address}:{client_port} 的UDP数据: {data}"
                )
                # 转换为Request对象
                request = Request.from_message(
                    msg=data, listener=self.name, remote_address=client_address
                )
                response = await self.handler(request)
                await send_udp(
                    anyio_socket, response, client, expiration=time() + self.timeout
                )
        except Exception as e:
            logger.error(f"处理UDP数据时发生错误: {e}")
        finally:
            await self._listener.aclose()

    async def stop(self):
        """停止UDP监听器"""
        if self._listener is not None:
            await self._listener.aclose()
            logger.info(f"UDP监听器 {self.name} 已停止")
