"""utls + anyio 的 DNS-over-TLS 传输层：加密流适配器与池化连接管理器。

utls.SSLContext 是 stdlib ssl 客户端子集的替身（BoringSSL 后端，可伪装
ClientHello 指纹），其 wrap_bio 的 server_hostname 只接受 str；而 anyio 的
TLSStream 会把 hostname 经 IDNA 编码成 bytes 传入 wrap_bio，因此这里自行
驱动握手与读写重试循环（语义对照 anyio TLSStream 的非标准模式），池内
保存握手完成的 TLSStreamConnection。DoT 的 2 字节长度前缀分帧与 DNS over
TCP 相同，报文收发由 dnspython 负责。
"""

import socket
import ssl
from typing import TYPE_CHECKING, Any

import utls
from anyio import EndOfStream, aclose_forcefully, connect_tcp, fail_after
from anyio.abc import SocketAttribute, SocketStream
from generic_connection_pool.asyncio import BaseConnectionManager

from smartdns.nameservers._pool import TcpEndpoint

if TYPE_CHECKING:
    from collections.abc import Callable

    from utls import MemoryBIO, SSLContext, SSLObject


class TLSStreamConnection:
    """utls 握手完成后的加密流，暴露 anyio ByteStream 形状的接口。

    AnyioStreamSocket 依赖 extra(SOCKET_*)、send、receive 与 aclose，分别转发
    给底层 TCP 流或加密层；aclose 不发 close_notify——池化语义下对端按 TCP
    断开处理，省一次关闭往返。
    """

    def __init__(
        self,
        transport: SocketStream,
        ssl_object: SSLObject,
        bio_in: MemoryBIO,
        bio_out: MemoryBIO,
    ) -> None:
        self._transport = transport
        self._ssl_object = ssl_object
        self._bio_in = bio_in
        self._bio_out = bio_out

    async def handshake(self) -> None:
        await self._drive(self._ssl_object.do_handshake)

    async def send(self, data: bytes) -> None:
        await self._drive(self._ssl_object.write, data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        try:
            return await self._drive(self._ssl_object.read, max_bytes)
        except ssl.SSLZeroReturnError:
            # 对端发送 close_notify：等价于流结束。
            return b""

    async def aclose(self) -> None:
        await self._transport.aclose()

    def extra(self, attribute: Any, default: Any = None) -> Any:
        # 委托底层 TCP 流：family、本地/对端地址与 raw_socket 继续可用。
        return self._transport.extra(attribute, default)

    async def _drive(self, func: Callable[..., Any], *args: Any) -> Any:
        """驱动一次 utls 非阻塞 SSL 操作，按 Want* 信号泵送两端 MemoryBIO。

        WantRead 时先冲刷出向密文再从传输流喂入入向；对端未发 close_notify
        直接断开（读侧 EOF）最终表现为 SSLEOFError，映射回 anyio EndOfStream。
        """
        while True:
            try:
                result = func(*args)
            except ssl.SSLWantReadError:
                await self._flush_outgoing()
                try:
                    data = await self._transport.receive()
                except EndOfStream:
                    self._bio_in.write_eof()
                else:
                    self._bio_in.write(data)
            except ssl.SSLWantWriteError:
                await self._flush_outgoing()
            except ssl.SSLEOFError:
                raise EndOfStream from None
            else:
                await self._flush_outgoing()
                return result

    async def _flush_outgoing(self) -> None:
        if self._bio_out.pending:
            await self._transport.send(self._bio_out.read())


async def start_tls(
    transport: SocketStream,
    ssl_context: SSLContext,
    server_hostname: str | None,
) -> TLSStreamConnection:
    """在已建立的 TCP 流上完成 utls 握手；失败（含取消）时关闭底层流。"""
    bio_in = utls.MemoryBIO()
    bio_out = utls.MemoryBIO()
    connection = TLSStreamConnection(
        transport,
        ssl_context.wrap_bio(bio_in, bio_out, server_hostname=server_hostname),
        bio_in,
        bio_out,
    )
    try:
        await connection.handshake()
    except BaseException:
        await aclose_forcefully(transport)
        raise
    return connection


async def connect_tls(
    host: str,
    port: int,
    ssl_context: SSLContext,
    server_hostname: str | None,
    connect_timeout: float,
) -> TLSStreamConnection:
    """建立 TCP 连接并完成 utls 握手；超时同时覆盖建连与握手。"""
    with fail_after(connect_timeout):
        transport = await connect_tcp(host, port)
        return await start_tls(transport, ssl_context, server_hostname)


class TLSStreamConnectionManager(
    BaseConnectionManager[TcpEndpoint, TLSStreamConnection]
):
    """utls + anyio 的 DoT 连接管理器，供 generic_connection_pool 复用加密连接。

    池内保存握手完成的 TLSStreamConnection；dnspython 的 dns.asyncquery.tcp 在
    传入 sock 时用 NullContext 包装、不会关闭它，连接可在多次查询间复用。
    """

    def __init__(
        self,
        ssl_context: SSLContext,
        server_hostname: str | None,
        connect_timeout: float = 5.0,
    ) -> None:
        self._ssl_context = ssl_context
        self._server_hostname = server_hostname
        self._connect_timeout = connect_timeout

    async def create(self, endpoint: TcpEndpoint) -> TLSStreamConnection:
        host, port = endpoint
        return await connect_tls(
            host,
            port,
            self._ssl_context,
            self._server_hostname,
            self._connect_timeout,
        )

    async def dispose(self, endpoint: TcpEndpoint, conn: TLSStreamConnection) -> None:
        await conn.aclose()

    async def check_aliveness(
        self, endpoint: TcpEndpoint, conn: TLSStreamConnection
    ) -> bool:
        raw = conn.extra(SocketAttribute.raw_socket, None)
        if raw is None:
            return False
        # asyncio 后端返回 TransportSocket，其他后端可能直接返回标准 socket。
        # peek 的是 TLS 密文：对端关闭返回 b""，无数据抛 BlockingIOError（存活），
        # 已缓冲 close_notify 的连接会在下次查询失败后由池回收。
        probe = getattr(raw, "_sock", raw)
        try:
            return probe.recv(1, socket.MSG_PEEK) != b""
        except BlockingIOError:
            return True
        except OSError:
            return False
