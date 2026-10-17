"""监听侧的 anyio → dnspython Socket 适配器。"""

from time import monotonic

from anyio import CancelScope, Lock, current_time

from smartdns.utils.sockets import (
    DatagramSocketAdapter,
    StreamSocketAdapter,
    dns_timeout,
)


class AnyioDatagramSocket(DatagramSocketAdapter):
    """未连接的监听 UDP 套接字：按目的地址发送，接收时返回对端地址。"""

    def __init__(self, sock):
        super().__init__(sock)
        # AnyIO UDPSocket 拒绝多个任务同时写入；Listener 会并发处理请求，
        # 因此在适配器边界将每个完整 datagram 的发送排队。
        self._send_lock = Lock()

    async def sendto(self, what, destination, timeout):
        with dns_timeout(timeout):
            async with self._send_lock:
                await self._sock.sendto(what, destination[0], destination[1])
        return len(what)

    async def recvfrom(self, size, timeout):
        with dns_timeout(timeout):
            data, addr = await self._sock.receive()
            return data[:size], addr


class AnyioStreamSocket(StreamSocketAdapter):
    """监听 TCP 连接：记录每条请求首字节到达的时刻，供请求期限从此计时。"""

    def __init__(self, stream):
        super().__init__(stream)
        self.request_started: float | None = None
        self._receive_scope: CancelScope | None = None
        self._receive_timeout = 0.0

    def begin_request(self, scope: CancelScope, timeout: float) -> None:
        self.request_started = None
        self._receive_scope = scope
        self._receive_timeout = timeout

    async def recv(self, size, timeout):
        data = await super().recv(size, timeout)
        if data and self.request_started is None:
            self.request_started = monotonic()
            if self._receive_scope is not None:
                # 空闲连接等待与单条帧的接收预算分别计时。
                self._receive_scope.deadline = current_time() + self._receive_timeout
        return data
