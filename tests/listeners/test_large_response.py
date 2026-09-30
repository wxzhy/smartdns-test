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


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
@pytest.mark.parametrize(
    ("rdtype", "addresses"),
    [
        ("A", ["192.0.2.3", "192.0.2.1", "192.0.2.2"]),
        ("AAAA", ["2001:db8::3", "2001:db8::1", "2001:db8::2"]),
    ],
)
def test_serialization_preserves_sorted_address_order(
    monkeypatch, protocol: str, rdtype: str, addresses: list[str]
) -> None:
    # 若序列化仍启用随机打乱，则用确定性的逆序替身让测试必然失败。
    monkeypatch.setattr(
        "dns.rdataset.random.shuffle", lambda records: records.reverse()
    )
    query = dns.message.make_query("example.com.", rdtype)
    records = "".join(f"example.com. 300 IN {rdtype} {ip}\n" for ip in addresses)
    response = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        f";QUESTION\nexample.com. IN {rdtype}\n;ANSWER\n" + records
    )

    wire = (
        _udp_listener()._serialize_response(query, response)
        if protocol == "udp"
        else _tcp_listener()._serialize_response(response)
    )
    parsed = dns.message.from_wire(wire)

    assert [record.address for record in parsed.answer[0]] == addresses
