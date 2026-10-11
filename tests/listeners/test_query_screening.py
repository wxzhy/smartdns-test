"""监听器入口报文筛查：坏包不拖停接收循环、应答报文丢弃、非 QUERY 返回 NOTIMP。"""

from socket import AF_INET, SOCK_DGRAM, socket
from time import perf_counter
from typing import TYPE_CHECKING, cast

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.tsigkeyring
from anyio import ClosedResourceError, create_task_group, fail_after, sleep, to_thread

from smartdns.listeners.tcp import TCPListener
from smartdns.listeners.udp import UDPListener
from smartdns.models.listener import Do53ListenerConfig
from tests.listeners.test_large_response import _large_txt_response
from tests.listeners.test_tcp_listener import _FakeStream

if TYPE_CHECKING:
    from anyio.abc import SocketStream

    from smartdns.models.context import Request


def _free_udp_port() -> int:
    with socket(AF_INET, SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _udp_listener(port: int = 5353) -> UDPListener:
    return UDPListener(
        Do53ListenerConfig(name="udp", type="udp", host="127.0.0.1", port=port)
    )


def _tsig_signed_query() -> bytes:
    query = dns.message.make_query("example.com.", "A")
    query.use_tsig(
        dns.tsigkeyring.from_text({"key.": "c2VjcmV0c2VjcmV0c2VjcmV0"}),
        keyname="key.",
    )
    return query.to_wire()


def _framed(message: dns.message.Message) -> bytes:
    wire = message.to_wire()
    return len(wire).to_bytes(2, "big") + wire


async def test_unparsable_datagrams_do_not_stall_udp_listener() -> None:
    port = _free_udp_port()
    listener = _udp_listener(port)
    handled: list[str] = []

    async def handler(request: Request) -> dns.message.Message:
        handled.append(str(request.qname))
        return request.make_error(dns.rcode.NOERROR)

    def client() -> float:
        with socket(AF_INET, SOCK_DGRAM) as sock:
            sock.settimeout(5)
            for _ in range(30):
                sock.sendto(_tsig_signed_query(), ("127.0.0.1", port))
            query = dns.message.make_query("ok.example.", "A").to_wire()
            started = perf_counter()
            sock.sendto(query, ("127.0.0.1", port))
            sock.recvfrom(4096)
            return perf_counter() - started

    async with create_task_group() as tg:
        tg.start_soon(listener.start, handler)
        await sleep(0.1)
        try:
            with fail_after(5):
                latency = await to_thread.run_sync(client)
        finally:
            await listener.stop()
            tg.cancel_scope.cancel()

    # 修复前每个 TSIG 报文令接收循环退避 0.1s，30 个即约 3s。
    assert latency < 1.0
    assert handled == ["ok.example."]


async def test_udp_listener_drops_responses_and_rejects_other_opcodes(
    monkeypatch,
) -> None:
    listener = _udp_listener()
    query = dns.message.make_query("query.example.", "A")
    reflected = dns.message.make_response(dns.message.make_query("r.example.", "A"))
    notify = dns.message.make_query("zone.example.", "SOA")
    notify.set_opcode(dns.opcode.NOTIFY)
    datagrams = iter([reflected.to_wire(), notify.to_wire(), query.to_wire()])
    sent: list[dns.message.Message] = []
    handled: list[str] = []

    class Datagram:
        def extra(self, attribute, default=None):
            return default

        async def receive(self):
            wire = next(datagrams, None)
            if wire is None:
                raise ClosedResourceError
            return wire, ("127.0.0.1", 12345)

        async def aclose(self):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return None

    class Factory:
        @classmethod
        async def from_socket(cls, sock):
            return Datagram()

    class RawSocket:
        def close(self) -> None:
            return None

    async def send(sock, wire, client, **kwargs):
        sent.append(dns.message.from_wire(wire))

    async def handler(request: Request) -> dns.message.Message:
        handled.append(str(request.qname))
        return request.make_error(dns.rcode.NOERROR)

    monkeypatch.setattr(listener, "_create_socket", RawSocket)
    monkeypatch.setattr("smartdns.listeners.udp.UDPSocket", Factory)
    monkeypatch.setattr("smartdns.listeners.udp.send_udp", send)
    with fail_after(5):
        # 接收结束后 start 会等待已派发的处理任务完成再返回。
        await listener.start(handler)

    assert handled == ["query.example."]
    assert len(sent) == 2
    rcodes = {message.opcode(): message.rcode() for message in sent}
    assert rcodes == {
        dns.opcode.NOTIFY: dns.rcode.NOTIMP,
        dns.opcode.QUERY: dns.rcode.NOERROR,
    }


async def test_tcp_listener_drops_responses_and_rejects_other_opcodes() -> None:
    reflected = dns.message.make_response(dns.message.make_query("r.example.", "A"))
    notify = dns.message.make_query("zone.example.", "SOA")
    notify.set_opcode(dns.opcode.NOTIFY)
    query = dns.message.make_query("query.example.", "A")
    stream = _FakeStream(_framed(reflected) + _framed(notify) + _framed(query))
    listener = TCPListener(
        Do53ListenerConfig(
            name="tcp", type="tcp", host="127.0.0.1", port=5353, timeout=0.3
        )
    )
    handled: list[str] = []

    async def handler(request: Request) -> dns.message.Message:
        handled.append(str(request.qname))
        return request.make_error(dns.rcode.NOERROR)

    listener.handler = handler
    # 回放完缓冲帧后读到 EOF；连接任务等待已派发的查询写回后才返回。
    stream.signal_eof()
    with fail_after(5):
        await listener.handle_connection(cast("SocketStream", stream))

    responses = [dns.message.from_wire(frame[2:]) for frame in stream.sent]
    assert handled == ["query.example."]
    rcodes = {message.opcode(): message.rcode() for message in responses}
    assert rcodes == {
        dns.opcode.NOTIFY: dns.rcode.NOTIMP,
        dns.opcode.QUERY: dns.rcode.NOERROR,
    }


def test_udp_response_size_is_capped_at_local_payload() -> None:
    query = dns.message.make_query("example.com.", "TXT", use_edns=True, payload=4096)
    wire = _udp_listener()._serialize_response(query, _large_txt_response(query))

    assert len(wire) <= 1232
    assert dns.message.from_wire(wire).flags & dns.flags.TC


def test_udp_tiny_advertised_payload_is_treated_as_512() -> None:
    query = dns.message.make_query("example.com.", "TXT", use_edns=True, payload=100)
    response = dns.message.make_response(query, our_payload=1232, pad=0)
    response.answer = dns.message.from_text(
        "id 1\nflags QR\n;QUESTION\nexample.com. IN TXT\n;ANSWER\n"
        'example.com. 300 IN TXT "' + "a" * 250 + '"\n'
    ).answer
    wire = _udp_listener()._serialize_response(query, response)

    assert 100 < len(wire) <= 512
    assert not dns.message.from_wire(wire).flags & dns.flags.TC
