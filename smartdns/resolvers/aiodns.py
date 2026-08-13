from typing import TYPE_CHECKING, cast

import dns.rdataclass
import dns.rdatatype
from aiodns import DNSResolver, query_type_map
from aiodns.error import ARES_ENODATA, ARES_ENOTFOUND, DNSError
from dns.message import Message, QueryMessage, make_query, make_response
from dns.name import Name, from_text
from dns.rcode import Rcode
from dns.rdata import from_wire
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.ANY.CAA import CAA
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.NS import NS
from dns.rdtypes.ANY.PTR import PTR
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TLSA import TLSA
from dns.rdtypes.ANY.TXT import TXT
from dns.rdtypes.ANY.URI import URI
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.IN.NAPTR import NAPTR
from dns.rdtypes.IN.SRV import SRV
from dns.rdtypes.svcbbase import GenericParam, ParamKey
from dns.resolver import NXDOMAIN, Answer, CacheKey
from dns.rrset import RRset
from loguru import logger
from pycares import (
    ARES_FLAG_EDNS,
    ARES_FLAG_USEVC,
    QUERY_TYPE_HTTPS,
    QUERY_TYPE_TLSA,
    QUERY_TYPE_URI,
    AAAARecordData,
    ARecordData,
    CAARecordData,
    CNAMERecordData,
    DNSRecord,
    DNSResult,
    HTTPSRecordData,
    MXRecordData,
    NAPTRRecordData,
    NSRecordData,
    PTRRecordData,
    SOARecordData,
    SRVRecordData,
    TLSARecordData,
    TXTRecordData,
    URIRecordData,
)

from smartdns.models.context import Request, Response
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.models.context import Context
    from smartdns.models.resolver import AioDNSResolverConfig

# 注册 pycares 未内置映射的记录类型（模块级，仅执行一次）。
query_type_map.update(
    {
        "HTTPS": QUERY_TYPE_HTTPS,
        "TLSA": QUERY_TYPE_TLSA,
        "URI": QUERY_TYPE_URI,
    }
)


class AioDNSResolver(BaseResolver):
    def __init__(self, config: AioDNSResolverConfig):
        super().__init__(config)
        self.edns = config.edns
        self.port = config.port
        self.tcp = config.tcp
        self.rotate = config.rotate
        self.tries = config.tries
        self.nameservers = [str(address) for address in config.nameservers]
        self._resolver: DNSResolver | None = None

    async def start(self):
        """启动解析器"""
        flags = 0
        if self.edns:
            flags |= ARES_FLAG_EDNS
        if self.tcp:
            flags |= ARES_FLAG_USEVC
        self._resolver = DNSResolver(
            nameservers=self.nameservers,
            timeout=self.timeout,
            flags=flags,
            tries=self.tries,
            rotate=self.rotate,
            tcp_port=self.port,
            udp_port=self.port,
        )

    async def stop(self):
        """停止解析器"""
        self._resolver = None

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """处理查询"""
        try:
            answer = await self.resolve(request.qname, request.rdtype, request.rdclass)
            return Response.from_answer(answer, upstream=self.name)
        except NXDOMAIN:
            return Response.from_rcode(Rcode.NXDOMAIN, upstream=self.name)
        except Exception:
            logger.exception(f"AioDNSResolver {self.name} 解析请求失败")
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

    async def resolve(
        self,
        qname: Name,
        rdtype: RdataType = RdataType.A,
        rdclass: RdataClass = RdataClass.IN,
    ) -> Answer:
        """解析域名"""
        if self._resolver is None:
            raise RuntimeError("解析器未启动")
        key: CacheKey = (qname, rdtype, rdclass)
        message = self.make_query(key)
        try:
            result = await self._resolver.query_dns(
                qname.to_text(),
                dns.rdatatype.to_text(rdtype),
                dns.rdataclass.to_text(rdclass),
            )
            message = self.make_response(message, result)

            return self.make_answer(key, message)
        except DNSError as e:
            code = e.args[0] if e.args else None
            if code == ARES_ENODATA:
                # 空数据（NODATA）：返回空的 NOERROR 应答。
                message = self.make_response(message)
                return self.make_answer(key, message)
            if code == ARES_ENOTFOUND:
                # 域名不存在：抛 NXDOMAIN，交由 query() 转为 NXDOMAIN 响应。
                raise NXDOMAIN(qnames=[qname]) from e
            raise

    def make_query(self, key: CacheKey) -> Message:
        """构造 DNS 查询消息。"""
        return make_query(key[0], key[1], key[2], use_edns=self.edns, payload=1232)

    @staticmethod
    def make_response(message: Message, result: DNSResult | None = None) -> Message:
        """将 pycares 的 DNSResult 填充为 dns 响应消息。"""
        answer = make_response(message, True, our_payload=1232, pad=0)
        answer.set_rcode(Rcode.NOERROR)
        if result is None:
            return answer
        for records, section in (
            (result.answer, answer.answer),
            (result.authority, answer.authority),
            (result.additional, answer.additional),
        ):
            for record in records:
                AioDNSResolver.merge_record(answer, section, record)
        # 关闭 RRset 索引（dnspython 运行期支持 index=None，其类型标注未含 None）。
        answer.index = None  # ty: ignore[invalid-assignment]
        return answer

    @staticmethod
    def merge_record(message: Message, section: list[RRset], record: DNSRecord) -> None:
        """将单条 pycares 记录合并到 section 中对应的标准 DNS RRset。"""
        incoming = AioDNSResolver.convert_record(record)
        rrset = message.find_rrset(
            section,
            incoming.name,
            incoming.rdclass,
            incoming.rdtype,
            covers=incoming.covers,
            deleting=incoming.deleting,
            create=True,
        )
        rrset.update(incoming)

    def make_answer(self, key: CacheKey, message: Message) -> Answer:
        """将消息包装为 dns.resolver.Answer 对象。"""
        nameserver = self.nameservers[0] if self.nameservers else ""
        return Answer(
            key[0],
            key[1],
            key[2],
            cast("QueryMessage", message),
            nameserver,
            self.port,
        )

    @staticmethod
    def convert_record(record: DNSRecord) -> RRset:
        """将pycares的DNSRecord对象转换为RRset对象"""
        name: Name = from_text(record.name)
        rdtype: RdataType = RdataType(record.type)
        rdclass: RdataClass = RdataClass(record.record_class)
        rrset: RRset = RRset(name, rdclass, rdtype)
        rrset.update_ttl(record.ttl)
        rdata = record.data
        match rdata:
            case ARecordData():
                rrset.add(A(rdclass, rdtype, rdata.addr))
            case AAAARecordData():
                rrset.add(AAAA(rdclass, rdtype, rdata.addr))
            case MXRecordData():
                rrset.add(MX(rdclass, rdtype, rdata.priority, rdata.exchange))
            case TXTRecordData():
                # pycares 5 将一个 TXT RR 内的 character-string 拼成单个 bytes，
                # 但 DNS wire 中每个 string 最长 255 字节。原始分段边界已丢失，
                # 因此按协议上限重新分段，至少保证长 TXT 可合法编码和转发。
                chunks = tuple(
                    rdata.data[offset : offset + 255]
                    for offset in range(0, len(rdata.data), 255)
                ) or (b"",)
                rrset.add(TXT(rdclass, rdtype, chunks))
            case CAARecordData():
                rrset.add(CAA(rdclass, rdtype, rdata.critical, rdata.tag, rdata.value))
            case CNAMERecordData():
                rrset.add(CNAME(rdclass, rdtype, rdata.cname))
            case HTTPSRecordData():
                params = {}
                for k, v in rdata.params:
                    # HTTPS记录的参数
                    key = ParamKey(k)
                    value = GenericParam(v)
                    params[key] = value
                rdata = HTTPS(rdclass, rdtype, rdata.priority, rdata.target, params)
                rdata_raw = rdata.to_wire()
                if not rdata_raw:
                    raise ValueError("HTTPS记录的rdata为空")
                new_rdata = from_wire(
                    rdclass, rdtype, rdata_raw, current=0, rdlen=len(rdata_raw)
                )
                rrset.add(new_rdata)
            case NAPTRRecordData():
                rrset.add(
                    NAPTR(
                        rdclass,
                        rdtype,
                        rdata.order,
                        rdata.preference,
                        rdata.flags,
                        rdata.service,
                        rdata.regexp,
                        rdata.replacement,
                    )
                )
            case NSRecordData():
                rrset.add(NS(rdclass, rdtype, rdata.nsdname))
            case PTRRecordData():
                rrset.add(PTR(rdclass, rdtype, rdata.dname))
            case SOARecordData():
                rrset.add(
                    SOA(
                        rdclass,
                        rdtype,
                        rdata.mname,
                        rdata.rname,
                        rdata.serial,
                        rdata.refresh,
                        rdata.retry,
                        rdata.expire,
                        rdata.minimum,
                    )
                )
            case SRVRecordData():
                rrset.add(
                    SRV(
                        rdclass,
                        rdtype,
                        rdata.priority,
                        rdata.weight,
                        rdata.port,
                        rdata.target,
                    )
                )
            case TLSARecordData():
                rrset.add(
                    TLSA(
                        rdclass,
                        rdtype,
                        rdata.cert_usage,
                        rdata.selector,
                        rdata.matching_type,
                        rdata.cert_association_data,
                    )
                )
            case URIRecordData():
                rrset.add(
                    URI(
                        rdclass,
                        rdtype,
                        rdata.priority,
                        rdata.weight,
                        rdata.target,
                    )
                )
            case _:
                raise ValueError(f"不支持的记录类型: {type(rdata)}")
        return rrset
