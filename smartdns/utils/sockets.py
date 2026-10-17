"""anyio 套接字到 dnspython 异步后端 Socket 接口的公共适配层。

dnspython 的 Datagram/StreamSocket 用 ``timeout`` 参数表达期限，并要求超时
抛出 ``dns.exception.Timeout``；监听侧与上游侧的适配器共用这里的超时转换与
地址查询方法，只各自实现收发细节。方法中的 ``timeout`` 形参是 dnspython
接口签名的一部分，不能改名。
"""

from __future__ import annotations

from contextlib import contextmanager
from socket import SOCK_DGRAM, SOCK_STREAM
from typing import TYPE_CHECKING, Any

from anyio import EndOfStream, fail_after
from anyio.abc import SocketAttribute
from dns._asyncbackend import DatagramSocket, StreamSocket
from dns.exception import Timeout

if TYPE_CHECKING:
    from collections.abc import Iterator


@contextmanager
def dns_timeout(timeout: float | None) -> Iterator[None]:
    """块内操作须在 timeout 秒内完成；超时转换为 dnspython 的 Timeout。"""
    try:
        with fail_after(timeout):
            yield
    except TimeoutError as err:
        raise Timeout(timeout=timeout) from err


def underlying_socket(stream: Any) -> Any:
    """取 anyio 流背后的标准 socket，取不到时返回 None。

    asyncio 后端暴露的是 TransportSocket（真实 socket 位于 ``_sock``），
    其他后端可能直接返回标准 socket。
    """
    raw = stream.extra(SocketAttribute.raw_socket, None)
    return None if raw is None else getattr(raw, "_sock", raw)


class DatagramSocketAdapter(DatagramSocket):
    """anyio UDP 套接字的 DatagramSocket 公共部分；子类实现 sendto/recvfrom。"""

    def __init__(self, sock: Any) -> None:
        self._sock = sock
        super().__init__(
            family=sock.extra(SocketAttribute.family, None), type=SOCK_DGRAM
        )

    async def close(self) -> None:
        await self._sock.aclose()

    async def getpeername(self) -> Any:
        return self._sock.extra(SocketAttribute.remote_address, None)

    async def getsockname(self) -> Any:
        return self._sock.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout: float) -> None:
        return None


class StreamSocketAdapter(StreamSocket):
    """anyio 字节流的 StreamSocket 实现；对端关闭时 recv 返回空字节表示 EOF。"""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        super().__init__(
            family=stream.extra(SocketAttribute.family, None), type=SOCK_STREAM
        )

    async def sendall(self, what: bytes, timeout: float | None) -> None:
        with dns_timeout(timeout):
            await self._stream.send(what)

    async def recv(self, size: int, timeout: float | None) -> bytes:
        try:
            with dns_timeout(timeout):
                return await self._stream.receive(size)
        except EndOfStream:
            return b""

    async def close(self) -> None:
        await self._stream.aclose()

    async def getpeername(self) -> Any:
        return self._stream.extra(SocketAttribute.remote_address, None)

    async def getsockname(self) -> Any:
        return self._stream.extra(SocketAttribute.local_address, None)

    async def getpeercert(self, timeout: float) -> None:
        return None
