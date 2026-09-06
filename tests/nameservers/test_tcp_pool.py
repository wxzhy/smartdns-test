"""Phase 3：TCP 连接池补全的针对性测试。

用本地回环 echo server 验证连接管理器的 create/check_aliveness/dispose 与连接池的
复用语义。另含名字服务器级的连接复用与脏连接重建测试（带 DNS 分帧的假服务器）。
"""

import asyncio
import struct
from typing import cast

import dns.asyncbackend
import dns.exception
import dns.message
import dns.rcode
import pytest
from generic_connection_pool.asyncio import ConnectionPool

from smartdns.models.nameserver import TCPNameserverConfig
from smartdns.nameservers._pool import TCPStreamConnectionManager
from smartdns.nameservers.tcp import TCPNameserver


def _dns_query():
    return dns.message.make_query("example.com.", "A")


def _dns_response():
    return dns.message.make_response(_dns_query())


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


async def test_tcp_nameserver_query_uses_remaining_deadline(monkeypatch) -> None:
    config = TCPNameserverConfig(
        name="t", type="tcp", address="127.0.0.1", port=53, timeout=1.0, pool_size=1
    )
    nameserver = TCPNameserver(config)
    pool = _SlowPool(delay=0.4)
    nameserver._pool = cast("ConnectionPool", pool)

    async def fake_query_on_stream(raw_sock, request, timeout, *args, **kwargs):
        pool.captured_timeouts.append(timeout)
        return _dns_response()

    monkeypatch.setattr(nameserver, "_query_on_stream", fake_query_on_stream)

    await nameserver.async_query(
        _dns_query(),
        1.0,
        None,
        0,
        False,
        cast("dns.asyncbackend.Backend", object()),
    )

    # 剩余时限 = 1.0 - acquire 延迟(≈0.4)，显著小于完整的 1.0。
    assert len(pool.captured_timeouts) == 1
    remaining = pool.captured_timeouts[0]
    assert 0.1 <= remaining < 0.9


async def test_tcp_nameserver_connect_times_out_without_pool(monkeypatch) -> None:
    """无池路径：黑洞地址建连在配置超时内被取消，而非悬挂到 OS 级超时。"""
    config = TCPNameserverConfig(
        name="t", type="tcp", address="192.0.2.1", port=53, timeout=0.3, pool_size=0
    )
    nameserver = TCPNameserver(config)

    async def hanging_connect(host: str, port: int) -> object:
        await asyncio.sleep(30)
        raise AssertionError("建连应已被超时取消")

    monkeypatch.setattr("smartdns.nameservers.tcp.connect_tcp", hanging_connect)

    # 传入 timeout=0（已到期），应回退到配置的 0.3 秒而不是被当作"未设置"。
    with pytest.raises(TimeoutError):
        await nameserver.async_query(
            _dns_query(),
            0,
            None,
            0,
            False,
            cast("dns.asyncbackend.Backend", object()),
        )


async def _start_echo_server() -> tuple[asyncio.Server, int]:
    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data or data == b"bye":
                    break
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_manager_create_check_dispose() -> None:
    server, port = await _start_echo_server()
    try:
        manager = TCPStreamConnectionManager(connect_timeout=2.0)
        endpoint = ("127.0.0.1", port)
        conn = await manager.create(endpoint)
        assert await manager.check_aliveness(endpoint, conn) is True
        await conn.send(b"hello")
        assert await conn.receive() == b"hello"
        await manager.dispose(endpoint, conn)
    finally:
        server.close()


async def test_pool_reuses_released_connection() -> None:
    server, port = await _start_echo_server()
    try:
        manager = TCPStreamConnectionManager(connect_timeout=2.0)
        pool = ConnectionPool(manager, min_idle=1, max_size=2, total_max_size=2)
        endpoint = ("127.0.0.1", port)
        async with pool.connection(endpoint, timeout=2.0) as s1:
            await s1.send(b"ping")
            assert await s1.receive() == b"ping"
            first = s1
        # 释放后再次获取应复用同一连接对象。
        async with pool.connection(endpoint, timeout=2.0) as s2:
            assert s2 is first
            await s2.send(b"pong")
            assert await s2.receive() == b"pong"
        await pool.close()
    finally:
        server.close()


async def test_check_aliveness_detects_closed_peer() -> None:
    server, port = await _start_echo_server()
    try:
        manager = TCPStreamConnectionManager(connect_timeout=2.0)
        endpoint = ("127.0.0.1", port)
        conn = await manager.create(endpoint)
        # 发送 "bye" 触发服务端主动关闭该连接。
        await conn.send(b"bye")
        await asyncio.sleep(0.1)  # 等待对端关闭传播
        assert await manager.check_aliveness(endpoint, conn) is False
        await manager.dispose(endpoint, conn)
    finally:
        server.close()


async def _start_framed_dns_server(state: dict) -> asyncio.Server:
    """带 DNS 分帧的假服务器：每个查询回一个完整分帧应答。"""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        state["connections"] += 1
        try:
            while True:
                (length,) = struct.unpack("!H", await reader.readexactly(2))
                payload = await reader.readexactly(length)
                query = dns.message.from_wire(payload)
                response = dns.message.make_response(query)
                wire = response.to_wire()
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
                state["exchanges"] += 1
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def test_nameserver_reuses_connection_across_queries() -> None:
    state = {"connections": 0, "exchanges": 0}
    server = await _start_framed_dns_server(state)
    port = server.sockets[0].getsockname()[1]
    try:
        nameserver = TCPNameserver(
            TCPNameserverConfig(
                name="t",
                type="tcp",
                address="127.0.0.1",
                port=port,
                timeout=2.0,
                pool_size=1,
            )
        )
        await nameserver.start()
        request = dns.message.make_query("example.com.", "A")
        for _ in range(2):
            response = await nameserver.async_query(
                request,
                2.0,
                None,
                0,
                False,
                cast("dns.asyncbackend.Backend", object()),
            )
            assert response.rcode() == dns.rcode.NOERROR
        await nameserver.stop()
        # 两次查询复用同一条池内连接。
        assert state["connections"] == 1
        assert state["exchanges"] == 2
    finally:
        server.close()


async def _start_partial_frame_server(state: dict) -> asyncio.Server:
    """首条连接只发半帧应答后悬挂，模拟应答途中断流；后续连接正常应答。"""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        state["connections"] += 1
        first = state["connections"] == 1
        try:
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            payload = await reader.readexactly(length)
            query = dns.message.from_wire(payload)
            wire = dns.message.make_response(query).to_wire()
            if first:
                writer.write(struct.pack("!H", len(wire)) + wire[: len(wire) // 2])
                await writer.drain()
                # 保持连接打开并悬挂，等客户端超时断开后经 EOF 退出。
                await reader.read()
            else:
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
                state["exchanges"] += 1
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def test_interrupted_exchange_rebuilds_connection() -> None:
    """交换中途超时的连接被标记脏并在下次获取时重建，第二次查询成功。

    半读应答的残留已被 asyncio 读入用户态缓冲，内核缓冲为空，MSG_PEEK
    探测不到；必须依赖交换方在异常时显式标记 healthy=False。
    """
    state = {"connections": 0, "exchanges": 0}
    server = await _start_partial_frame_server(state)
    port = server.sockets[0].getsockname()[1]
    try:
        nameserver = TCPNameserver(
            TCPNameserverConfig(
                name="t",
                type="tcp",
                address="127.0.0.1",
                port=port,
                timeout=0.3,
                pool_size=1,
            )
        )
        await nameserver.start()
        request = dns.message.make_query("example.com.", "A")
        with pytest.raises(dns.exception.Timeout):
            await nameserver.async_query(
                request,
                0.3,
                None,
                0,
                False,
                cast("dns.asyncbackend.Backend", object()),
            )
        response = await nameserver.async_query(
            request,
            2.0,
            None,
            0,
            False,
            cast("dns.asyncbackend.Backend", object()),
        )
        assert response.rcode() == dns.rcode.NOERROR
        await nameserver.stop()
        # 超时打断的连接未复用：第二次查询在新连接上完成。
        assert state["connections"] == 2
        assert state["exchanges"] == 1
    finally:
        server.close()
