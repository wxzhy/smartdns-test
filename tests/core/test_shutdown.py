"""显式停机关闭已有 TCP 连接，多个停机调用也等待资源释放。"""

import asyncio
import struct
from contextlib import suppress
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.message
from anyio import Event, fail_after
from anyio.abc import SocketAttribute

from smartdns.actions import _ping
from smartdns.core.master import Master
from smartdns.listeners import tcp as tcp_module
from smartdns.listeners.tcp import TCPListener
from smartdns.models.http import HTTPClientConfig
from smartdns.models.listener import Do53ListenerConfig
from smartdns.nameservers import client

if TYPE_CHECKING:
    from smartdns.models.config import Config


async def test_explicit_concurrent_stop_closes_live_tcp_connection(monkeypatch) -> None:
    # 实际启动会设置进程级缓存，结束后恢复，避免污染后续测速测试。
    monkeypatch.setattr(_ping.SPEEDTEST_CACHE, "cache", None)
    monkeypatch.setattr(client.ECH_CACHE, "cache", None)
    ready = Event()
    original = tcp_module.create_tcp_listener

    async def create_listener(*args, **kwargs):
        listener = await original(*args, **kwargs)
        ready.set()
        return listener

    monkeypatch.setattr(tcp_module, "create_tcp_listener", create_listener)
    listener = Do53ListenerConfig(
        name="test", type="tcp", host="127.0.0.1", port=5353, timeout=5
    ).model_copy(update={"port": 0})
    config = cast(
        "Config",
        SimpleNamespace(
            worker_count=1,
            cache_size=10,
            client=HTTPClientConfig(max_clients=1),
            geodata=None,
            listeners=[listener],
            nameservers=[],
            resolvers=[],
            actions=[],
            routing=[],
        ),
    )
    master = Master(config)
    serving = asyncio.create_task(master.start())
    try:
        with fail_after(3):
            await ready.wait()
            assert master.listener_manager is not None
            tcp = master.listener_manager.listeners[0]
            assert isinstance(tcp, TCPListener)
            assert tcp._listener is not None
            port = tcp._listener.listeners[0].extra(SocketAttribute.local_port)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            workers = list(master.workers)
            try:
                wire = dns.message.make_query("example.com.", "A").to_wire()
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
                length = struct.unpack("!H", await reader.readexactly(2))[0]
                await reader.readexactly(length)
                await asyncio.gather(master.stop(), master.stop())
                await serving
                with suppress(ConnectionResetError):
                    assert await reader.read(1) == b""
                assert master.workers == []
                assert all(
                    worker._loop is None and not worker._tasks for worker in workers
                )
                assert master.listener_manager is None
                assert master._shared_deadlines == {}
            finally:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()
    finally:
        if not serving.done():
            serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
