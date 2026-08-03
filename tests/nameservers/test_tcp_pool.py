"""Phase 3：TCP 连接池补全的针对性测试。

用本地回环 echo server 验证连接管理器的 create/check_aliveness/dispose 与连接池的
复用语义。不涉及 DNS 报文分帧——那部分由 dnspython 的 dns.asyncquery.tcp 负责。
"""

import asyncio

from generic_connection_pool.asyncio import ConnectionPool

from smartdns.nameservers._pool import TCPStreamConnectionManager


async def _start_echo_server() -> tuple[asyncio.AbstractServer, int]:
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
