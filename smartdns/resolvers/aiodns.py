from typing import cast

from aiodns import DNSResolver, query_type_map
from aiodns.error import ARES_ENODATA, DNSError
from dns.message import Message, QueryMessage, make_query, make_response
from dns.name import Name, from_text
from dns.rcode import Rcode
import dns.rdatatype
import dns.rdataclass
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
from dns.resolver import Answer, CacheKey
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
from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.resolvers.base import BaseResolver


class AioDNSResolver(BaseResolver):
    def __init__(self, config: AioDNSResolverConfig):
        super().__init__(config)
        self.edns = config.edns
        self.port = config.port
        self.tcp = config.tcp
        self.rotate = config.rotate
        self.tries = config.tries
        self.nameservers = config.nameservers
        # 添加HTTPS和TLS解析器类型
        query_type_map.update({
            "HTTPS": QUERY_TYPE_HTTPS,
            "TLSA": QUERY_TYPE_TLSA,
            "URI": QUERY_TYPE_URI,
        })
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

    async def query(self, request: Request) -> Response:
        if self._resolver is None:
            raise RuntimeError("解析器未启动")
        key = (request.qname, request.rdtype, request.rdclass)
        message = self.make_query(key)
        try:
            result = await self._resolver.query_dns(
                request.qname.to_text(),
                dns.rdatatype.to_text(request.rdtype),
                dns.rdataclass.to_text(request.rdclass),
            )
            message = self.make_response(message, result)
            answer = self.make_answer(key, message)
            return Response.from_answer(answer, upstream=self.config.name)
        except DNSError as e:
            code = e.args[0]
            if code == ARES_ENODATA:
                # 响应为空时正常处理，默认行为
                message = self.make_response(message)
                answer = self.make_answer(key, message)
                return Response.from_answer(answer, upstream=self.config.name)
            logger.error(
                f"AioDNSResolver {self.config.name} 解析请求 {request} 时发生错误: {e}"
            )
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.config.name)

        except Exception as e:
            logger.exception(
                f"AioDNSResolver {self.config.name} 解析请求 {request} 时发生错误: {e}"
            )
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.config.name)

    def make_query(self, key: CacheKey) -> Message:
        """将pycares的DNSResult对象转换为dns.resolver.Answer对象"""
        query = make_query(key[0], key[1], key[2], use_edns=self.edns, payload=1232)
        return query

    @staticmethod
    def make_response(message: Message, result: DNSResult | None = None) -> Message:
        """将pycares的DNSResult对象转换为dns.resolver.Answer对象"""
        answer = make_response(message, True, our_payload=1232, pad=0)
        answer.set_rcode(Rcode.NOERROR)
        if result is None:
            return answer
        # 将pycares的DNSResult对象转换为dns.resolver.Answer对象
        for record in result.answer:
            rrset = AioDNSResolver.convert_record(record)
            answer.answer.append(rrset)
        for record in result.authority:
            rrset = AioDNSResolver.convert_record(record)
            answer.authority.append(rrset)
        for record in result.additional:
            rrset = AioDNSResolver.convert_record(record)
            answer.additional.append(rrset)
        return answer

    def make_answer(self, key: CacheKey, message: Message):
        """转换为dns.resolver.Answer对象"""
        return Answer(
            key[0],
            key[1],
            key[2],
            cast("QueryMessage", message),
            self.nameservers[0],
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
                rrset.add(TXT(rdclass, rdtype, (rdata.data,)))
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
                rrset.add(HTTPS(rdclass, rdtype, rdata.priority, rdata.target, params))
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
