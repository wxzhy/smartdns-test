"""AioDNSResolver 对 pycares 长 TXT 数据的转换回归测试。"""

from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from pycares import DNSRecord, TXTRecordData

from smartdns.resolvers.aiodns import AioDNSResolver


def _record(data: bytes) -> DNSRecord:
    return DNSRecord(
        name="example.com.",
        type=RdataType.TXT,
        record_class=RdataClass.IN,
        ttl=300,
        data=TXTRecordData(data),
    )


def test_long_txt_data_is_split_into_wire_safe_chunks() -> None:
    data = bytes(index % 256 for index in range(700))

    rrset = AioDNSResolver.convert_record(_record(data))
    txt = next(iter(rrset))

    assert [len(chunk) for chunk in txt.strings] == [255, 255, 190]
    assert b"".join(txt.strings) == data
    assert len(txt.to_wire()) == 703


def test_empty_txt_data_remains_a_valid_empty_string() -> None:
    rrset = AioDNSResolver.convert_record(_record(b""))
    txt = next(iter(rrset))

    assert txt.strings == (b"",)
    assert txt.to_wire() == b"\x00"
