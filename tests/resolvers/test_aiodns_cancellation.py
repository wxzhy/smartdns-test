"""原生 c-ares 取消隔离、重试停止以及通道负载上限。"""

import asyncio
from typing import TYPE_CHECKING, cast

import dns.message
import dns.rrset
import pytest
from anyio import Event, fail_after, sleep
from anyio.lowlevel import checkpoint
from dns.name import from_text
from pycares import DNSResult

from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.resolvers._aiodns_pool import AioDNSPool
from smartdns.resolvers.aiodns import AioDNSResolver

if TYPE_CHECKING:
    from aiodns import DNSResolver


class _NativeServer(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: dict[str, list[tuple[dns.message.Message, tuple[str, int]]]] = {}
        self.cancelled_arrived = Event()
        self.live_arrived = Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        query = dns.message.from_wire(data)
        name = query.question[0].name.to_text()
        self.received.setdefault(name, []).append((query, addr))
        if name == "cancel.example.":
            self.cancelled_arrived.set()
        if name == "live.example.":
            self.live_arrived.set()

    def reply(self, transport: asyncio.DatagramTransport, name: str) -> None:
        query, addr = self.received[name][-1]
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "192.0.2.1"))
        transport.sendto(response.to_wire(), addr)


async def test_cancel_stops_native_retries_without_cancelling_other_query() -> None:
    loop = asyncio.get_running_loop()
    server = _NativeServer()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: server, local_addr=("127.0.0.1", 0)
    )
    resolver = AioDNSResolver(
        AioDNSResolverConfig(
            name="a",
            type="aiodns",
            nameservers=["127.0.0.1"],
            port=transport.get_extra_info("sockname")[1],
            timeout=0.1,
            tries=3,
            max_queries=2,
            cache_size=0,
        )
    )
    await resolver.start()
    cancelled = asyncio.create_task(resolver.resolve(from_text("cancel.example.")))
    live: asyncio.Task | None = None
    try:
        with fail_after(2):
            await server.cancelled_arrived.wait()
            live = asyncio.create_task(resolver.resolve(from_text("live.example.")))
            await server.live_arrived.wait()
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            server.reply(transport, "live.example.")
            answer = await live
            assert answer.rrset is not None
            assert answer.rrset[0].address == "192.0.2.1"
        await sleep(0.8)
        assert len(server.received["cancel.example."]) == 1
    finally:
        cancelled.cancel()
        if live is not None:
            live.cancel()
        await resolver.stop()
        await asyncio.gather(
            cancelled, *([live] if live is not None else []), return_exceptions=True
        )
        transport.close()


class _Channel:
    def __init__(self) -> None:
        self.started = Event()
        self.result = asyncio.get_running_loop().create_future()
        self.cancel_count = 0
        self.closed = False

    async def query_dns(self, *args) -> DNSResult:
        self.started.set()
        return await self.result

    def cancel(self) -> None:
        self.cancel_count += 1
        self.result.cancel()

    async def close(self) -> None:
        self.closed = True
        self.result.cancel()


async def test_native_limit_blocks_submission_and_queue_cancel_is_isolated() -> None:
    channels: list[_Channel] = []

    def factory() -> DNSResolver:
        channel = _Channel()
        channels.append(channel)
        return cast("DNSResolver", channel)

    pool = AioDNSPool(factory, max_queries=1)
    first = asyncio.create_task(pool.query_dns("first", "A", "IN"))
    await channels[0].started.wait()
    second = asyncio.create_task(pool.query_dns("second", "A", "IN"))
    await checkpoint()
    assert len(channels) == 1
    second.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second
    assert channels[0].cancel_count == 0
    result = DNSResult(answer=[], authority=[], additional=[])
    channels[0].result.set_result(result)
    assert await first is result
    await pool.close()
    assert channels[0].closed
