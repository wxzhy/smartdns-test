"""TLS Nameserver 传输层、连接池与配置语义测试。

本地回环 TCP 服务器 + 注入的假 ssl_object（identity 密码层）绕开真实证书
依赖：write 原样进 bio_out、read 从 bio_in 取"明文"，握手序列可编排，
从而真实验证握手循环、加密流适配器、连接池复用与 dns.asyncquery.tcp 全链路。
"""

import asyncio
import ssl as stdlib_ssl
import struct
from typing import TYPE_CHECKING, cast

import anyio
import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.rcode
import pytest
import utls
from anyio import EndOfStream
from generic_connection_pool.asyncio import ConnectionPool

from smartdns.models.nameserver import TLSNameserverConfig
from smartdns.nameservers._socket import AnyioStreamSocket
from smartdns.nameservers._tls import (
    TLSStreamConnection,
    TLSStreamConnectionManager,
)
from smartdns.nameservers.manager import NameserverManager
from smartdns.nameservers.tls import TLSNameserver

if TYPE_CHECKING:
    from anyio.abc import SocketStream
    from utls import MemoryBIO, SSLContext, SSLObject

    from smartdns.nameservers._pool import TcpEndpoint
    from smartdns.nameservers.client import HTTPClient


class _FakeSSLObject:
    """identity 密码层的假 SSLObject：以真实 Want* 异常驱动重试循环。"""

    def __init__(
        self, bio_in: MemoryBIO, bio_out: MemoryBIO, handshake_rounds: int = 0
    ):
        self._bio_in = bio_in
        self._bio_out = bio_out
        self._handshake_rounds = handshake_rounds
        self.handshake_done = False

    def do_handshake(self) -> bool:
        if self._handshake_rounds:
            self._handshake_rounds -= 1
            self._bio_out.write(f"hs{self._handshake_rounds}".encode())
            raise stdlib_ssl.SSLWantWriteError
        self.handshake_done = True
        return True

    def write(self, data: bytes) -> int:
        self._bio_out.write(data)
        return len(data)

    def read(self, n: int) -> bytes:
        # 对端 EOF 后必须抛 SSLEOFError，与真实 BoringSSL 行为一致。
        if self._bio_in.eof:
            raise stdlib_ssl.SSLEOFError
        if self._bio_in.pending == 0:
            raise stdlib_ssl.SSLWantReadError
        return self._bio_in.read(n)


def _connection(
    transport: SocketStream, handshake_rounds: int = 0
) -> TLSStreamConnection:
    bio_in = utls.MemoryBIO()
    bio_out = utls.MemoryBIO()
    fake = _FakeSSLObject(bio_in, bio_out, handshake_rounds)
    return TLSStreamConnection(transport, cast("SSLObject", fake), bio_in, bio_out)


async def _start_record_echo_server() -> tuple[
    asyncio.AbstractServer, int, list[bytes]
]:
    """回显服务器：记录收到的每个分片并原样回发；收到 b"bye" 后关闭连接。"""
    received: list[bytes] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data or data == b"bye":
                    break
                received.append(data)
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, received


async def test_handshake_flushes_ciphertext_in_order() -> None:
    server, port, received = await _start_record_echo_server()
    try:
        transport = await anyio.connect_tcp("127.0.0.1", port)
        bio_in = utls.MemoryBIO()
        bio_out = utls.MemoryBIO()
        fake = _FakeSSLObject(bio_in, bio_out, handshake_rounds=2)
        conn = TLSStreamConnection(transport, cast("SSLObject", fake), bio_in, bio_out)
        await conn.handshake()
        await asyncio.sleep(0.1)  # 等待服务器协程记录收到的密文
        # 两轮 WantWrite 的密文按产生顺序冲刷到传输流（TCP 可能合并分片）。
        assert b"".join(received) == b"hs1hs0"
        assert fake.handshake_done
        await conn.aclose()
    finally:
        server.close()


async def test_send_receive_round_trip() -> None:
    server, port, received = await _start_record_echo_server()
    try:
        transport = await anyio.connect_tcp("127.0.0.1", port)
        conn = _connection(transport)
        await conn.send(b"ping")
        assert await conn.receive(1024) == b"ping"
        assert received == [b"ping"]
        await conn.aclose()
    finally:
        server.close()


async def test_receive_maps_peer_close_to_end_of_stream() -> None:
    server, port, _received = await _start_record_echo_server()
    try:
        transport = await anyio.connect_tcp("127.0.0.1", port)
        conn = _connection(transport)
        await conn.send(b"bye")  # 服务器收到 bye 后主动关闭连接
        with pytest.raises(EndOfStream):
            await conn.receive(1024)
    finally:
        server.close()


async def test_manager_create_dispose_and_aliveness(monkeypatch) -> None:
    server, port, _received = await _start_record_echo_server()
    try:
        endpoint: TcpEndpoint = ("127.0.0.1", port)
        manager = TLSStreamConnectionManager(
            cast("SSLContext", object()), None, connect_timeout=2.0
        )

        async def fake_start_tls(transport, ssl_context, server_hostname):
            return _connection(transport)

        monkeypatch.setattr("smartdns.nameservers._tls.start_tls", fake_start_tls)
        conn = await manager.create(endpoint)
        assert await manager.check_aliveness(endpoint, conn) is True
        await conn.send(b"hello")
        assert await conn.receive(64) == b"hello"
        await manager.dispose(endpoint, conn)
    finally:
        server.close()


async def test_manager_aliveness_detects_closed_peer(monkeypatch) -> None:
    server, port, _received = await _start_record_echo_server()
    try:
        endpoint: TcpEndpoint = ("127.0.0.1", port)
        manager = TLSStreamConnectionManager(
            cast("SSLContext", object()), None, connect_timeout=2.0
        )

        async def fake_start_tls(transport, ssl_context, server_hostname):
            return _connection(transport)

        monkeypatch.setattr("smartdns.nameservers._tls.start_tls", fake_start_tls)
        conn = await manager.create(endpoint)
        await conn.send(b"bye")  # 服务器主动关闭该连接
        await asyncio.sleep(0.1)  # 等待对端关闭传播
        assert await manager.check_aliveness(endpoint, conn) is False
        await manager.dispose(endpoint, conn)
    finally:
        server.close()


async def test_pool_reuses_tls_connection(monkeypatch) -> None:
    server, port, _received = await _start_record_echo_server()
    try:
        endpoint: TcpEndpoint = ("127.0.0.1", port)
        manager = TLSStreamConnectionManager(
            cast("SSLContext", object()), None, connect_timeout=2.0
        )

        async def fake_start_tls(transport, ssl_context, server_hostname):
            return _connection(transport)

        monkeypatch.setattr("smartdns.nameservers._tls.start_tls", fake_start_tls)
        pool = ConnectionPool(manager, min_idle=1, max_size=2, total_max_size=2)
        async with pool.connection(endpoint, timeout=2.0) as s1:
            await s1.send(b"ping")
            assert await s1.receive(64) == b"ping"
            first = s1
        # 释放后再次获取应复用同一加密连接对象。
        async with pool.connection(endpoint, timeout=2.0) as s2:
            assert s2 is first
            await s2.send(b"pong")
            assert await s2.receive(64) == b"pong"
        await pool.close()
    finally:
        server.close()


async def test_dns_asyncquery_tcp_over_tls_connection() -> None:
    """带 2 字节分帧的假 DNS 服务器：AnyioStreamSocket + dns.asyncquery.tcp 全链路。"""
    query = dns.message.make_query("example.com.", "A")

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            header = await reader.readexactly(2)
            (length,) = struct.unpack("!H", header)
            payload = await reader.readexactly(length)
            response = dns.message.make_response(dns.message.from_wire(payload))
            wire = response.to_wire()
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        transport = await anyio.connect_tcp("127.0.0.1", port)
        conn = _connection(transport)
        message = await dns.asyncquery.tcp(
            query,
            where="127.0.0.1",
            timeout=2.0,
            port=port,
            sock=AnyioStreamSocket(conn),
        )
        assert message.id == query.id
        assert message.rcode() == dns.rcode.NOERROR
        await conn.aclose()
    finally:
        server.close()


class _SlowPool:
    """伪连接池：acquire 阻塞指定时长后交出连接并记录查询时限。"""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self.captured_timeouts: list[float] = []

    def connection(self, endpoint, timeout: float):
        pool = self

        class _Ctx:
            async def __aenter__(self):
                await asyncio.sleep(pool._delay)
                return object()

            async def __aexit__(self, *exc_info) -> None:
                return None

        return _Ctx()


async def test_tls_nameserver_query_uses_remaining_deadline(monkeypatch) -> None:
    config = TLSNameserverConfig(
        name="t", type="tls", address="127.0.0.1", port=8853, timeout=1.0, pool_size=1
    )
    nameserver = TLSNameserver(config)
    pool = _SlowPool(delay=0.4)
    nameserver._pool = cast("ConnectionPool", pool)

    async def fake_query_on_stream(raw_sock, request, timeout, *args, **kwargs):
        pool.captured_timeouts.append(timeout)
        return dns.message.make_response(dns.message.make_query("example.com.", "A"))

    monkeypatch.setattr(nameserver, "_query_on_stream", fake_query_on_stream)

    await nameserver.async_query(
        dns.message.make_query("example.com.", "A"),
        1.0,
        None,
        0,
        False,
        cast("dns.asyncbackend.Backend", object()),
    )

    # 剩余时限 = 1.0 - acquire 延迟(≈0.4)，显著小于完整的 1.0。
    assert len(pool.captured_timeouts) == 1
    assert 0.1 <= pool.captured_timeouts[0] < 0.9


async def test_tls_nameserver_connect_times_out_without_pool(monkeypatch) -> None:
    """无池路径：黑洞地址建连在配置超时内被取消，而非悬挂到 OS 级超时。"""
    config = TLSNameserverConfig(
        name="t", type="tls", address="192.0.2.1", port=853, timeout=0.3, verify=False
    )
    nameserver = TLSNameserver(config)

    async def hanging_connect(host: str, port: int) -> object:
        await asyncio.sleep(30)
        raise AssertionError("建连应已被超时取消")

    monkeypatch.setattr("smartdns.nameservers._tls.connect_tcp", hanging_connect)

    # 传入 timeout=0（已到期），应回退到配置的 0.3 秒而不是被当作"未设置"。
    with pytest.raises(TimeoutError):
        await nameserver.async_query(
            dns.message.make_query("example.com.", "A"),
            0,
            None,
            0,
            False,
            cast("dns.asyncbackend.Backend", object()),
        )


def test_server_hostname_resolution() -> None:
    # 显式 server_name 优先。
    override = TLSNameserver(
        TLSNameserverConfig(
            name="a",
            type="tls",
            address="1.2.3.4",
            server_name="dns.example.com",
            verify=False,
        )
    )
    assert override._server_hostname == "dns.example.com"
    # 域名地址用地址本身。
    domain = TLSNameserver(
        TLSNameserverConfig(name="b", type="tls", address="dns.google", verify=False)
    )
    assert domain._server_hostname == "dns.google"
    # IP 地址不发 SNI。
    literal = TLSNameserver(
        TLSNameserverConfig(name="c", type="tls", address="8.8.8.8", verify=False)
    )
    assert literal._server_hostname is None


async def test_start_rejects_verify_without_hostname() -> None:
    config = TLSNameserverConfig(name="t", type="tls", address="8.8.8.8", port=853)
    nameserver = TLSNameserver(config)
    with pytest.raises(ValueError, match="server_name"):
        await nameserver.start()


async def test_start_rejects_unknown_fingerprint() -> None:
    config = TLSNameserverConfig(
        name="t", type="tls", address="dns.google", fingerprint="nope:1"
    )
    nameserver = TLSNameserver(config)
    with pytest.raises(ValueError, match="unknown preset"):
        await nameserver.start()


async def test_start_builds_context_without_verify() -> None:
    config = TLSNameserverConfig(
        name="t",
        type="tls",
        address="8.8.8.8",
        verify=False,
        fingerprint="chrome:stable",
    )
    nameserver = TLSNameserver(config)
    await nameserver.start()
    context = nameserver._ssl_context
    assert context is not None
    assert context.check_hostname is False
    assert context.verify_mode == utls.CERT_NONE
    assert context.fingerprint is not None
    await nameserver.stop()


async def test_default_fingerprint_is_chrome_stable() -> None:
    # 未配置 fingerprint 时默认以 chrome:stable 预设伪装 ClientHello。
    config = TLSNameserverConfig(
        name="t", type="tls", address="dns.google", verify=False
    )
    assert config.fingerprint == "chrome:stable"
    nameserver = TLSNameserver(config)
    await nameserver.start()
    context = nameserver._ssl_context
    assert context is not None
    assert context.fingerprint is not None
    await nameserver.stop()


async def test_start_creates_pool_and_stop_closes() -> None:
    config = TLSNameserverConfig(
        name="t", type="tls", address="dns.google", pool_size=2
    )
    nameserver = TLSNameserver(config)
    await nameserver.start()
    assert nameserver._pool is not None
    await nameserver.stop()
    assert nameserver._pool is None


async def test_nameserver_manager_registers_tls() -> None:
    config = TLSNameserverConfig(
        name="tls-main", type="tls", address="dns.google", pool_size=0
    )
    manager = NameserverManager([config], cast("HTTPClient", None))
    await manager.start_all()
    try:
        nameserver = manager.get("tls-main")
        assert isinstance(nameserver, TLSNameserver)
        assert nameserver.kind() == "tls"
    finally:
        await manager.stop_all()
