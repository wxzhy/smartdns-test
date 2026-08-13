"""大 DNS 响应在 UDP/TCP 监听边界的序列化回归测试。"""

import dns.flags
import dns.message
import pytest
from dns.exception import TooBig

from smartdns.listeners.tcp import TCPListener
from smartdns.listeners.udp import UDPListener
from smartdns.models.listener import Do53ListenerConfig


def _large_txt_response(query: dns.message.Message) -> dns.message.Message:
    records = "".join(
        f'example.com. 300 IN TXT "{chr(65 + index % 26) * 190}"\n'
        for index in range(14)
    )
    upstream = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN TXT\n;ANSWER\n" + records
    )
    response = dns.message.make_response(
        query, recursion_available=True, our_payload=1232, pad=0
    )
    response.answer = upstream.answer
    return response


def _udp_listener() -> UDPListener:
    return UDPListener(
        Do53ListenerConfig(name="udp", type="udp", host="127.0.0.1", port=5353)
    )


def _tcp_listener() -> TCPListener:
    return TCPListener(
        Do53ListenerConfig(name="tcp", type="tcp", host="127.0.0.1", port=5353)
    )


def test_udp_edns_large_response_is_truncated_instead_of_failing() -> None:
    query = dns.message.make_query("example.com.", "TXT", use_edns=True, payload=1232)
    response = _large_txt_response(query)

    with pytest.raises(TooBig):
        response.to_wire()

    wire = _udp_listener()._serialize_response(query, response)
    parsed = dns.message.from_wire(wire)

    assert len(wire) <= 1232
    assert parsed.flags & dns.flags.TC


def test_udp_without_edns_uses_legacy_512_byte_limit() -> None:
    query = dns.message.make_query("example.com.", "TXT")
    response = _large_txt_response(query)

    wire = _udp_listener()._serialize_response(query, response)
    parsed = dns.message.from_wire(wire)

    assert len(wire) <= 512
    assert parsed.flags & dns.flags.TC


def test_tcp_serialization_can_return_the_full_large_response() -> None:
    query = dns.message.make_query("example.com.", "TXT", use_edns=True, payload=1232)
    response = _large_txt_response(query)

    wire = _tcp_listener()._serialize_response(response)
    parsed = dns.message.from_wire(wire)

    assert len(wire) > 1232
    assert not parsed.flags & dns.flags.TC
    assert sum(len(rrset) for rrset in parsed.answer) == 14
