"""TCP 监听器处理超时与并发连接上限的回归测试。"""

from socket import AF_INET
from time import monotonic
from typing import TYPE_CHECKING, cast

import dns.message
from anyio import EndOfStream, Event, create_task_group, fail_after, sleep
from anyio.abc import SocketAttribute

from smartdns.listeners.tcp import TCPListener
from smartdns.models.listener import Do53ListenerConfig

if TYPE_CHECKING:
    from anyio.abc import SocketStream

    from smartdns.models.context import Request


class _FakeStream:
    """模拟 anyio SocketStream：先回放一个查询报文，可发 EOF 或永久阻塞。"""

    def __init__(self, payload: bytes | None = None) -> None:
        self._pending = payload
        self._blocked = Event()
        self._eof = Event()
        self.sent: list[bytes] = []
        self.closed = False

    def signal_eof(self) -> None:
        self._eof.set()
        # 真实套接字关闭会唤醒正在等待的 receive；测试替身需保持同样语义。
        self._blocked.set()

    def extra(self, attribute: object, default: object = None) -> object:
        if attribute is SocketAttribute.family:
            return AF_INET
        if attribute is SocketAttribute.remote_address:
            return ("192.0.2.10", 53000)
        return default

    async def receive(self, max_bytes: int) -> bytes:
        if self._pending:
            data, self._pending = self._pending[:max_bytes], self._pending[max_bytes:]
            return data
        if self._eof.is_set():
            raise EndOfStream
        await self._blocked.wait()
        return b""  # pragma: no cover - 阻塞事件未释放时的兜底

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def aclose(self) -> None:
        self.closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()


def _query_payload() -> bytes:
    wire = dns.message.make_query("example.com.", "A").to_wire()
    return len(wire).to_bytes(2, "big") + wire


def _listener(timeout: float, max_connections: int = 256) -> TCPListener:
    return TCPListener(
        Do53ListenerConfig(
            name="tcp", type="tcp", host="127.0.0.1", port=5353, timeout=timeout
        ),
        max_connections=max_connections,
    )


async def test_handle_connection_times_out_slow_handler() -> None:
    stream = _FakeStream(_query_payload())
    listener = _listener(timeout=0.2)

    async def slow_handler(request: Request):
        await sleep(10)

    listener.handler = slow_handler
    started = monotonic()
    await listener.handle_connection(cast("SocketStream", stream))
    elapsed = monotonic() - started

    assert 0.15 <= elapsed < 1.0
    assert stream.closed
    assert stream.sent == []  # 未产出应答


async def test_handle_connection_drops_empty_question_query() -> None:
    # 空 question 报文被跳过，连接保持等待下一个查询，由空闲超时退出。
    empty = dns.message.make_query("example.com.", "A")
    empty.question = []
    payload = empty.to_wire()
    stream = _FakeStream(len(payload).to_bytes(2, "big") + payload)
    listener = _listener(timeout=0.1)
    calls: list[object] = []

    async def handler(request: Request):
        calls.append(request)

    listener.handler = handler
    started = monotonic()
    await listener.handle_connection(cast("SocketStream", stream))
    assert monotonic() - started < 5
    assert calls == []
    assert stream.sent == []


async def test_handle_connection_processes_pipelined_queries_concurrently() -> None:
    first = dns.message.make_query("first.example.com.", "A")
    second = dns.message.make_query("second.example.com.", "A")
    first.id = 0x1001
    second.id = 0x1002
    payload = b"".join(
        len(wire).to_bytes(2, "big") + wire
        for wire in (first.to_wire(), second.to_wire())
    )
    stream = _FakeStream(payload)
    stream.signal_eof()
    listener = _listener(timeout=1)
    release_first = Event()
    second_started = Event()

    async def handler(request: Request):
        if request.msg.id == first.id:
            await release_first.wait()
        else:
            second_started.set()
            release_first.set()
        return dns.message.make_response(request.msg)

    listener.handler = handler
    with fail_after(2):
        await listener.handle_connection(cast("SocketStream", stream))

    assert second_started.is_set()
    assert len(stream.sent) == 2
    for frame in stream.sent:
        assert int.from_bytes(frame[:2], "big") == len(frame) - 2
    response_ids = {dns.message.from_wire(frame[2:]).id for frame in stream.sent}
    assert response_ids == {first.id, second.id}


async def test_pipelined_handler_error_is_isolated_to_one_query() -> None:
    failed = dns.message.make_query("failed.example.com.", "A")
    successful = dns.message.make_query("successful.example.com.", "A")
    failed.id = 0x2001
    successful.id = 0x2002
    payload = b"".join(
        len(wire).to_bytes(2, "big") + wire
        for wire in (failed.to_wire(), successful.to_wire())
    )
    stream = _FakeStream(payload)
    stream.signal_eof()
    listener = _listener(timeout=1)

    async def handler(request: Request):
        if request.msg.id == failed.id:
            raise RuntimeError("query failed")
        return dns.message.make_response(request.msg)

    listener.handler = handler
    with fail_after(2):
        await listener.handle_connection(cast("SocketStream", stream))

    assert len(stream.sent) == 1
    assert dns.message.from_wire(stream.sent[0][2:]).id == successful.id


async def test_partial_response_write_closes_pipelined_connection() -> None:
    first = dns.message.make_query("first.example.com.", "A")
    second = dns.message.make_query("second.example.com.", "A")
    payload = b"".join(
        len(wire).to_bytes(2, "big") + wire
        for wire in (first.to_wire(), second.to_wire())
    )

    class _PartiallyFailingStream(_FakeStream):
        def __init__(self) -> None:
            super().__init__(payload)
            self.send_calls = 0
            self.sent_bytes = bytearray()

        async def send(self, data: bytes) -> None:
            self.send_calls += 1
            if self.send_calls == 1:
                self.sent_bytes.extend(data[:4])
                raise OSError("partial write")
            self.sent_bytes.extend(data)

    stream = _PartiallyFailingStream()
    stream.signal_eof()
    listener = _listener(timeout=1)
    second_started = Event()

    async def handler(request: Request):
        if request.qname == first.question[0].name:
            await second_started.wait()
        else:
            second_started.set()
            await sleep(0.1)
        return dns.message.make_response(request.msg)

    listener.handler = handler
    with fail_after(2):
        await listener.handle_connection(cast("SocketStream", stream))

    assert second_started.is_set()
    assert stream.send_calls == 1
    assert stream.closed


class _FakeAcceptor:
    """模拟 anyio TCPListener：依次交出预置连接，耗尽后阻塞。"""

    def __init__(self, streams: list[_FakeStream]) -> None:
        self._streams = list(streams)
        self._exhausted = Event()
        self.accepted_two = Event()
        self.accepted_count = 0
        self.closed = False
        self.listeners = [self]

    async def accept(self) -> _FakeStream:
        if self._streams:
            stream = self._streams.pop(0)
            self.accepted_count += 1
            if self.accepted_count >= 2:
                self.accepted_two.set()
            return stream
        await self._exhausted.wait()
        raise AssertionError  # pragma: no cover - 阻塞事件未释放时的兜底

    async def aclose(self) -> None:
        self.closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()


async def test_tcp_listener_limits_concurrent_connections(monkeypatch) -> None:
    streams = [_FakeStream(_query_payload()) for _ in range(3)]
    acceptor = _FakeAcceptor(streams)

    async def fake_create_tcp_listener(**kwargs):
        return acceptor

    monkeypatch.setattr(
        "smartdns.listeners.tcp.create_tcp_listener", fake_create_tcp_listener
    )

    listener = _listener(timeout=30, max_connections=2)
    entered = 0
    second_entered = Event()
    third_entered = Event()
    release = Event()

    async def handler(request: Request):
        nonlocal entered
        entered += 1
        if entered == 2:
            second_entered.set()
        if entered == 3:
            third_entered.set()
        await release.wait()

    async with create_task_group() as tg:
        tg.start_soon(listener.start, handler)
        with fail_after(5):
            await second_entered.wait()
        assert entered == 2  # 第三个连接被并发上限挡住
        release.set()
        for stream in streams:
            stream.signal_eof()  # 前两个连接正常终结，释放并发额度
        with fail_after(5):
            await third_entered.wait()
        assert entered == 3  # 前两个完成后第三个进入
        tg.cancel_scope.cancel()


async def test_cancel_closes_connection_waiting_for_capacity(monkeypatch) -> None:
    """停机取消发生在限流等待期间时，已 accept 的连接也必须关闭。"""
    streams = [_FakeStream(_query_payload()) for _ in range(2)]
    acceptor = _FakeAcceptor(streams)

    async def fake_create_tcp_listener(**kwargs):
        return acceptor

    monkeypatch.setattr(
        "smartdns.listeners.tcp.create_tcp_listener", fake_create_tcp_listener
    )

    listener = _listener(timeout=30, max_connections=1)
    first_entered = Event()
    release = Event()

    async def handler(request: Request):
        first_entered.set()
        await release.wait()

    async with create_task_group() as tg:
        tg.start_soon(listener.start, handler)
        with fail_after(5):
            await first_entered.wait()
            await acceptor.accepted_two.wait()
        assert not streams[1].closed
        tg.cancel_scope.cancel()

    assert streams[1].closed
