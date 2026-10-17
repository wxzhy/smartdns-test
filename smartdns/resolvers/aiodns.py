"""基于 aiodns（c-ares）的解析器：把 pycares 结果重新组装为 dnspython Answer。"""

from time import time
from typing import TYPE_CHECKING, cast

import dns.rdataclass
import dns.rdatatype
from aiodns import DNSResolver, query_type_map
from aiodns.error import ARES_ENODATA, ARES_ENOTFOUND, DNSError
from dns.message import Message, QueryMessage, make_query
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

from smartdns.actions._helper import detach_index, replay_answer
from smartdns.models.context import EDNS_PAYLOAD, Request, Response, reply_to
from smartdns.resolvers._aiodns_pool import AioDNSPool
from smartdns.resolvers.base import BaseResolver
from smartdns.utils.cache_async import AnswerCache

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
        self.max_queries = config.max_queries
        self.nodata_ttl = config.nodata_ttl
        self.nameservers = [str(address) for address in config.nameservers]
        self._resolver: AioDNSPool | None = None
        # 应答缓存（AnswerCache）：相同完整配置跨 Worker 线程共享；同名但配置
        # 不同的解析器彼此隔离。cache_size=0 关闭。挂在 resolve() 边界，
        # query() 与 HTTPClient 的 ECH 引导查询共用同一缓存。
        if config.cache_size > 0:
            self._cache: AnswerCache[CacheKey, Answer] | None = AnswerCache.shared(
                f"aiodns:{config.model_dump_json()}", config.cache_size
            )
        else:
            self._cache = None

    async def start(self):
        """启动解析器"""
        flags = 0
        if self.edns:
            flags |= ARES_FLAG_EDNS
        if self.tcp:
            flags |= ARES_FLAG_USEVC
        self._resolver = AioDNSPool(
            lambda: DNSResolver(
                nameservers=self.nameservers,
                timeout=self.timeout,
                flags=flags,
                tries=self.tries,
                rotate=self.rotate,
                tcp_port=self.port,
                udp_port=self.port,
            ),
            self.max_queries,
        )

    async def stop(self):
        """停止解析器"""
        resolver = self._resolver
        self._resolver = None
        if resolver is not None:
            await resolver.close()

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """处理查询"""
        try:
            answer = await self.resolve(request.qname, request.rdtype, request.rdclass)
            return Response.from_answer(replay_answer(answer), upstream=self.name)
        except DNSError as error:
            # c-ares 的超时、SERVFAIL、REFUSED 等属常规故障，不打印堆栈。
            logger.warning(
                "AioDNSResolver {} 解析 {} 失败: {}",
                self.name,
                request.qname,
                error,
            )
            return Response.servfail(self.name)
        except Exception:
            logger.exception("AioDNSResolver {} 解析 {} 出错", self.name, request.qname)
            return Response.servfail(self.name)

    async def resolve(
        self,
        qname: Name,
        rdtype: RdataType = RdataType.A,
        rdclass: RdataClass = RdataClass.IN,
    ) -> Answer:
        """解析域名；缓存开启时经 AnswerCache（同键并发合并为一次上游查询）。"""
        cache = self._cache
        if cache is None:
            return await self._resolve_once(qname, rdtype, rdclass)
        return await cache.fetch(
            (qname, rdtype, rdclass),
            lambda: self._resolve_once(qname, rdtype, rdclass),
        )

    async def _resolve_once(
        self,
        qname: Name,
        rdtype: RdataType = RdataType.A,
        rdclass: RdataClass = RdataClass.IN,
    ) -> Answer:
        """单次上游解析，不经过缓存。"""
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
            if code not in (ARES_ENODATA, ARES_ENOTFOUND):
                raise
            # 否定应答：ENODATA 为空的 NOERROR（NODATA），ENOTFOUND 为 NXDOMAIN。
            # pycares 不携带上游 SOA，空报文无记录可压 TTL，Answer.expiration
            # 会取 dnspython 的 MAX_TTL（约 136 年）；显式设置负缓存 TTL，
            # 使两级缓存都能按 nodata_ttl 缓存否定结果。
            message = self.make_response(message)
            if code == ARES_ENOTFOUND:
                message.set_rcode(Rcode.NXDOMAIN)
            answer = self.make_answer(key, message)
            answer.expiration = time() + self.nodata_ttl
            return answer

    def make_query(self, key: CacheKey) -> Message:
        """构造 DNS 查询消息。"""
        return make_query(*key, use_edns=self.edns, payload=EDNS_PAYLOAD)

    @staticmethod
    def make_response(message: Message, result: DNSResult | None = None) -> Message:
        """将 pycares 的 DNSResult 填充为 dns 响应消息。"""
        answer = reply_to(message)
        if result is None:
            return answer
        for records, section in (
            (result.answer, answer.answer),
            (result.authority, answer.authority),
            (result.additional, answer.additional),
        ):
            for record in records:
                AioDNSResolver.merge_record(answer, section, record)
        # 索引只在组装时有用；缓存中的应答不必长期持有这份额外引用。
        detach_index(answer)
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
