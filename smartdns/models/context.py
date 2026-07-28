from __future__ import annotations

from dns.message import Message, make_response
from dns.name import Name
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer
from loguru import logger
from pydantic import ConfigDict, Field
from pydantic.dataclasses import dataclass
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class IPInfo:
    """IP 运行时信息。"""

    ip: IPvAnyAddress
    asn: int | None = None
    country: set[str] | None = None
    rtt: float | None = None
    resolver: str | None = None

    @classmethod
    def from_ip(cls, ip: IPvAnyAddress) -> IPInfo:
        """从IP地址创建IPInfo对象"""
        return cls(ip=ip)


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class NameInfo:
    """域名运行时信息。"""

    name: Name
    country: set[str] | None = None

    @classmethod
    def from_name(cls, name: Name) -> NameInfo:
        """从域名创建NameInfo对象"""
        return cls(name=name)


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class Request:
    """请求数据类"""

    id: int
    listener: str
    msg: Message
    remote_address: IPvAnyAddress | None
    qname: Name
    rdtype: RdataType
    rdclass: RdataClass
    name_info: NameInfo
    ip_info: IPInfo | None
    ecs: IPvAnyNetwork | None = None
    ecs_info: IPInfo | None = None

    def __str__(self):
        return f"Request from {self.remote_address}\n{self.msg}"

    def make_answer(self, ans: Answer) -> Message:
        """创建响应对象"""
        answer = make_response(self.msg, True, our_payload=1232, pad=0)
        answer.set_rcode(Rcode.NOERROR)
        answer.answer = ans.response.answer
        answer.authority = ans.response.authority
        answer.additional = ans.response.additional
        return answer

    def make_error(self, rcode: Rcode) -> Message:
        """创建错误响应对象"""
        response = make_response(self.msg, True, our_payload=1232, pad=0)
        response.set_rcode(rcode)
        return response

    @classmethod
    def from_message(
        cls, msg: Message, listener: str, remote_address: IPvAnyAddress | None = None
    ) -> Request:
        """从dns.message.Message对象创建Request对象"""
        question = msg.question[0]
        qname = question.name
        rdtype = question.rdtype
        rdclass = question.rdclass
        return cls(
            id=msg.id,
            listener=listener,
            msg=msg,
            remote_address=remote_address,
            qname=qname,
            rdtype=rdtype,
            rdclass=rdclass,
            name_info=NameInfo.from_name(qname),
            ip_info=IPInfo.from_ip(remote_address) if remote_address else None,
        )


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class Response:
    """响应数据类"""

    rcode: Rcode
    ans: Answer | None = None
    upstream: str = ""
    invalid: bool = False
    ip_list: list[IPvAnyAddress] | None = None
    name_list: list[Name] | None = None
    canonical_name: Name | None = None
    ip_infos: list[IPInfo] | None = None
    name_infos: list[NameInfo] | None = None

    @classmethod
    def from_rcode(cls, rcode: Rcode, upstream: str) -> Response:
        """从rcode创建Response对象"""
        return cls(rcode=rcode, upstream=upstream, invalid=True)

    @classmethod
    def from_answer(cls, answer: Answer, upstream: str) -> Response | None:
        """从dns.resolver.Answer对象创建Response对象"""
        rcode = answer.response.rcode()
        if rcode != Rcode.NOERROR:
            logger.info(f"上游返回错误码: {rcode}")
            return None
        response = cls(rcode, answer, upstream)
        response.name_list, response.name_infos = [], []
        # 处理CNAME链
        for cname in answer.chaining_result.cnames:
            for rr in cname:
                response.name_list.append(rr.target)
                response.name_infos.append(NameInfo.from_name(rr.target))
        # 处理IP列表
        if answer.rdtype in (RdataType.A, RdataType.AAAA) and answer.rrset is not None:
            response.ip_list, response.ip_infos = [], []
            for rr in answer.rrset:
                response.ip_list.append(rr.address)
                response.ip_infos.append(IPInfo.from_ip(rr.address))
        return response

    def __str__(self):
        return f"Received rcode {self.rcode} answer {self.ans.response if self.ans else None} from upstream={self.upstream}"


@dataclass
class Context:
    """worker 处理期间贯穿所有 hook 的全局上下文。"""

    worker_id: int
    request: Request
    # 当前处理的响应对象
    response: Response | None = None
    # 结果列表
    candidates: list[Response] | None = None
    stop: bool = False
    is_subquery: bool = False
    subquery: Context | None = None
    ext: dict = Field(default_factory=dict, description="扩展字段，用于存储额外信息")
