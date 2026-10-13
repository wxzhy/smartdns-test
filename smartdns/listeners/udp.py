"""Do53 UDP 监听器。"""

from socket import (
    AF_INET6,
    IPPROTO_IPV6,
    IPV6_V6ONLY,
    SO_REUSEADDR,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)
from sys import platform
from time import monotonic, time
from typing import TYPE_CHECKING

from anyio import ClosedResourceError, Semaphore, create_task_group, fail_after, sleep
from anyio.abc import UDPSocket
from dns.asyncquery import send_udp
from dns.inet import af_for_address
from dns.message import from_wire
from loguru import logger

from smartdns.listeners._socket import AnyioDatagramSocket
from smartdns.listeners.base import BaseListener, remaining, should_drop

if TYPE_CHECKING:
    from dns.message import Message

    from smartdns.listeners.base import Handler
    from smartdns.models.listener import Do53ListenerConfig

if platform == "win32":
    from socket import SO_EXCLUSIVEADDRUSE
else:
    from socket import SO_REUSEPORT

_RECEIVE_ERROR_BACKOFF = 0.1
# 与 make_response 宣告的 our_payload 一致：客户端声明更大的 payload 也不超过
# 此值，避免 UDP 放大与 IP 分片（DNS Flag Day 2020 建议值）。
_MAX_UDP_PAYLOAD = 1232


class UDPListener(BaseListener):
    """UDP 监听器：单个套接字接收，每个请求在独立任务中处理并回写。"""

    transport = "UDP"

    def __init__(self, config: Do53ListenerConfig):
        super().__init__(config)
        self.host = str(config.host) if config.host is not None else "::"
        self.port = config.port
        self.reuse_port = config.reuse_port
        self._family = af_for_address(self.host)
        self._listener: UDPSocket | None = None
        self._sock: socket | None = None

    def _create_socket(self) -> socket:
        """创建并绑定 UDP 套接字。仅 IPv6 设置双栈 V6ONLY=0，避免 IPv4 下崩溃。"""
        sock = socket(self._family, SOCK_DGRAM)
        try:
            if self._family == AF_INET6:
                sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            sock.setblocking(False)
            if platform == "win32":
                sock.setsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
                if self.reuse_port:
                    logger.warning("UDP 监听器 {}: Windows 忽略 reuse_port", self.name)
            else:
                sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                if self.reuse_port:
                    sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
            sock.bind((self.host, self.port))
            return sock
        except BaseException:
            sock.close()
            raise

    @staticmethod
    def _serialize_response(request: Message, response: Message) -> bytes:
        """按客户端声明的 UDP 容量序列化，超限时返回带 TC 的合法响应。

        RFC 6891：小于 512 的声明按 512 处理；上限取本端宣告的 payload。
        """
        max_size = (
            min(max(request.payload, 512), _MAX_UDP_PAYLOAD)
            if request.edns >= 0
            else 512
        )
        # 保留 speedcheck 等动作排定的记录顺序。
        return response.to_wire(
            max_size=max_size,
            prefer_truncation=True,
            # dnspython 误标 **kw 类型；Rdataset.to_wire 接受 bool。
            want_shuffle=False,  # ty: ignore[invalid-argument-type]
        )

    async def start(self, handler: Handler):
        """启动UDP监听器并进入接收循环。"""
        self.handler = handler
        # 套接字在 start 时创建/绑定（而非 __init__），避免构造副作用与泄漏。
        self._sock = self._create_socket()
        try:
            self._listener = await UDPSocket.from_socket(self._sock)
        except BaseException:
            # from_socket 失败时不会替我们接管原始 socket，必须主动关闭。
            self._sock.close()
            self._sock = None
            raise
        logger.info(
            "UDP 监听器 {} 已启动，监听地址: {}:{}", self.name, self.host, self.port
        )
        async with self._listener:
            anyio_socket = AnyioDatagramSocket(self._listener)
            limiter = Semaphore(256)

            async def process(msg: Message, client: tuple, deadline: float) -> None:
                try:
                    if deadline <= monotonic():
                        return
                    with self.log_failures(), fail_after(remaining(deadline)):
                        response = await self.answer(msg, client[0], deadline)
                        if response is not None:
                            wire = self._serialize_response(msg, response)
                            await send_udp(
                                anyio_socket,
                                wire,
                                client,
                                expiration=time() + remaining(deadline),
                            )
                finally:
                    limiter.release()

            async with create_task_group() as tg:
                while True:
                    try:
                        wire, client = await anyio_socket.recvfrom(65535, None)
                    except ClosedResourceError:
                        break
                    except Exception as error:
                        # 套接字及其他持续性接收故障采用短退避，避免错误热循环。
                        logger.warning(
                            "UDP 监听器 {} 接收请求失败: {}: {}",
                            self.name,
                            type(error).__name__,
                            error,
                        )
                        await sleep(_RECEIVE_ERROR_BACKOFF)
                        continue
                    try:
                        msg = from_wire(wire, ignore_trailing=True)
                    except Exception as error:
                        # 解析失败只说明单个报文有问题（畸形、TSIG 签名等），丢弃后
                        # 立即继续接收；退避会让任意客户端用坏包拖停整个监听器。
                        logger.debug(
                            "UDP 监听器 {} 丢弃无法解析的请求: {}: {}",
                            self.name,
                            type(error).__name__,
                            error,
                        )
                        continue
                    if should_drop(msg):
                        logger.debug(
                            "UDP 监听器 {} 丢弃应答报文或无 question 报文", self.name
                        )
                        continue
                    deadline = monotonic() + self.timeout
                    try:
                        with fail_after(max(0.0, deadline - monotonic())):
                            await limiter.acquire()
                    except TimeoutError:
                        logger.warning("UDP 监听器 {} 请求排队超时", self.name)
                        continue
                    try:
                        tg.start_soon(process, msg, client, deadline)
                    except BaseException:
                        limiter.release()
                        raise

    async def stop(self):
        """停止UDP监听器并释放套接字。"""
        if self._listener is not None:
            await self._listener.aclose()
            self._listener = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        logger.info("UDP 监听器 {} 已停止", self.name)
