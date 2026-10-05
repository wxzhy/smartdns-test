"""真实 UDP/TCP → Master → Worker 链路在外层期限前保留已有答案。"""

import asyncio
import struct
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.message
import dns.rrset
import pytest
from anyio import (
    Event,
    create_connected_udp_socket,
    create_task_group,
    fail_after,
    sleep,
)
from anyio.abc import SocketAttribute
from anyio.from_thread import start_blocking_portal
from dns.rcode import Rcode
from dns.resolver import Answer

from smartdns.core.master import Master
from smartdns.core.worker import Worker
from smartdns.listeners import tcp as tcp_module
from smartdns.listeners.tcp import TCPListener
from smartdns.listeners.udp import UDPListener
from smartdns.models.context import Context, Request, Response
from smartdns.models.http import HTTPClientConfig
from smartdns.models.listener import Do53ListenerConfig
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.models.rule import Rule
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from typing import Literal

    from dns.message import QueryMessage

    from smartdns.actions.base import BaseAction
    from smartdns.actions.manager import ActionManager
    from smartdns.models.config import Config
    from smartdns.resolvers.manager import ResolverManager


class _Upstream:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, request: Request, context: Context | None = None) -> Response:
        assert request.deadline is not None
        if self.name == "slow":
            await sleep(10)
        message = dns.message.make_response(request.msg)
        message.answer.append(
            dns.rrset.from_text(request.qname, 60, "IN", "A", "192.0.2.1")
        )
        answer = Answer(
            request.qname,
            request.rdtype,
            request.rdclass,
            cast("QueryMessage", message),
        )
        return Response.from_answer(answer, upstream=self.name)


class _Manager:
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values

    def get(self, name: str):
        return self.values.get(name)


class _After:
    async def on_response(self, context: Context) -> None:
        await sleep(10)


@pytest.mark.parametrize("kind", ["udp", "tcp"])
@pytest.mark.parametrize("cache_size", [0, 10])
@pytest.mark.parametrize("slow_after", [False, True])
async def test_completed_answer_reaches_client_before_listener_deadline(
    kind: str, cache_size: int, slow_after: bool, monkeypatch
) -> None:
    config = cast(
        "Config",
        SimpleNamespace(
            worker_count=1,
            cache_size=cache_size,
            client=HTTPClientConfig(max_clients=1),
            nameservers=[],
            resolvers=[],
            actions=[],
            routing=[],
        ),
    )
    with start_blocking_portal() as portal:
        worker = Worker(0, config)
        portal.call(worker.start)
        managers = _Manager({"fast": _Upstream("fast"), "slow": _Upstream("slow")})
        actions = cast("ActionManager", _Manager({}))
        concurrent = ConcurrentResolver(
            ConcurrentResolverConfig(
                name="race",
                type="concurrent",
                timeout=0.35,
                wait_all=not slow_after,
                resolvers=["fast", "slow"],
            ),
            cast("ResolverManager", managers),
            actions,
        )
        router = Router(
            Rule(name="test", resolver="race"),
            cast("ResolverManager", _Manager({"race": concurrent})),
            actions,
        )
        if slow_after:
            router.after = [cast("BaseAction", _After())]
        worker._rules = [router]
        master = Master(config)
        master.workers = [worker]
        master.portals = [portal]
        listener_config = Do53ListenerConfig(
            name="test",
            type=cast("Literal['udp', 'tcp']", kind),
            host="127.0.0.1",
            port=5353,
            timeout=0.35,
        )
        listener = (
            UDPListener(listener_config)
            if kind == "udp"
            else TCPListener(listener_config)
        )
        listener.port = 0
        ready = Event()
        ports: list[int] = []
        if isinstance(listener, UDPListener):
            original = listener._create_socket

            def create_socket():
                sock = original()
                ports.append(sock.getsockname()[1])
                ready.set()
                return sock

            monkeypatch.setattr(listener, "_create_socket", create_socket)
        else:
            original_tcp = tcp_module.create_tcp_listener

            async def create_listener(**kwargs):
                result = await original_tcp(**kwargs)
                ports.append(result.listeners[0].extra(SocketAttribute.local_port))
                ready.set()
                return result

            monkeypatch.setattr(tcp_module, "create_tcp_listener", create_listener)

        query = dns.message.make_query("example.com.", "A")
        try:
            async with create_task_group() as tg:
                tg.start_soon(listener.start, master.dispatch)
                with fail_after(2):
                    await ready.wait()
                    if kind == "tcp":
                        reader, writer = await asyncio.open_connection(
                            "127.0.0.1", ports[0]
                        )
                        try:
                            wire = query.to_wire()
                            writer.write(struct.pack("!H", len(wire)) + wire)
                            await writer.drain()
                            size = struct.unpack("!H", await reader.readexactly(2))[0]
                            response = dns.message.from_wire(
                                await reader.readexactly(size)
                            )
                        finally:
                            writer.close()
                            await writer.wait_closed()
                    else:
                        async with await create_connected_udp_socket(
                            remote_host="127.0.0.1", remote_port=ports[0]
                        ) as client:
                            await client.send(query.to_wire())
                            response = dns.message.from_wire(await client.receive())
                    assert query.is_response(response)
                    assert response.rcode() == Rcode.NOERROR
                    assert response.answer[0][0].address == "192.0.2.1"
                await listener.stop()
                tg.cancel_scope.cancel()
        finally:
            await asyncio.wrap_future(worker.submit(worker.stop()))
