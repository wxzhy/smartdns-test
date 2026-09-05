from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from dns.edns import ECSOption
from dns.exception import FormError
from dns.message import Message, make_query, make_response
from dns.name import Name
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import IPv4HintParam, IPv6HintParam
from dns.resolver import Answer
from pydantic import ConfigDict, Field
from pydantic.dataclasses import dataclass
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork

from smartdns.models.geodata import IPInfo, NameInfo


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
        return (
            f"Request from {self.remote_address}\n{self.msg}\n"
            f"IP: {self.ip_info}\nName: {self.name_info}\nECS: {self.ecs_info}"
        )

    def make_answer(self, ans: Answer) -> Message:
        """创建响应对象；rcode 跟随上游应答（NXDOMAIN 等负应答保留原语义）。"""
        answer = make_response(self.msg, True, our_payload=1232, pad=0)
        answer.set_rcode(ans.response.rcode())
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
        if not msg.question:
            # 残缺报文（QDCOUNT=0）无法构造查询上下文；监听器应在入口预检丢弃。
            raise FormError("DNS message has no question")
        question = msg.question[0]
        qname = question.name
        rdtype = question.rdtype
        rdclass = question.rdclass
        ecs = None
        for option in msg.options:
            if isinstance(option, ECSOption):
                ecs = ip_network(f"{option.address}/{option.srclen}", strict=False)
                break
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
            ecs=ecs,
            ecs_info=IPInfo.from_ip(ecs.network_address) if ecs is not None else None,
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
        return cls(rcode=rcode, upstream=upstream, invalid=False)

    @classmethod
    def from_answer(cls, answer: Answer, upstream: str) -> Response:
        """从dns.resolver.Answer对象创建Response对象。

        非 NOERROR 的负应答同样保留 ans（含 authority 区 SOA），
        供上游透传给客户端做负缓存。
        """
        rcode = answer.response.rcode()
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
                response.ip_infos.append(IPInfo.from_ip(rr.address, resolver=upstream))
        elif answer.rdtype == RdataType.HTTPS and answer.rrset is not None:
            response.ip_list, response.ip_infos = [], []
            for rr in answer.rrset:
                for param in rr.params.values():
                    # HTTPS记录的ipv4hint/ipv6hint参数包含了IP地址列表
                    if isinstance(param, (IPv4HintParam, IPv6HintParam)):
                        for ip in param.addresses:
                            response.ip_list.append(ip)
                            response.ip_infos.append(
                                IPInfo.from_ip(ip, resolver=upstream)
                            )
        return response

    def __str__(self):
        answer = self.ans.response if self.ans else None
        return (
            f"Received rcode {self.rcode} answer {answer} "
            f"from upstream={self.upstream}\n"
            f"IPs: {self.ip_infos}\nNames: {self.name_infos}"
        )


@dataclass(slots=True)
class Context:
    """worker 处理期间贯穿所有 hook 的全局上下文。"""

    worker_id: int
    request: Request
    # 当前处理的响应对象
    response: Response | None = None
    # 结果列表
    candidates: dict[str, Response] | None = None
    ip_infos: dict[IPvAnyAddress, IPInfo] | None = None
    stop: bool = False
    # ConcurrentResolver 打在嵌套解析器子上下文上的内部查询标记
    is_subquery: bool = False
    # on_response 阶段由 Action 设置；Router 以当前 resolver 执行后回调 on_subquery
    subquery: Context | None = None
    ext: dict[str, Any] = Field(
        default_factory=dict, description="扩展字段，用于存储额外信息"
    )

    @classmethod
    def for_subquery(
        cls,
        context: Context,
        qname: Name | None = None,
        rdtype: RdataType | None = None,
    ) -> Context:
        """从现有上下文派生子查询上下文，供 Action 在 on_response 阶段设置。

        新请求默认沿用原查询的 qname/rdtype/rdclass、监听器与客户端地址；
        传入 qname/rdtype 可派生查询其他目标的子请求。
        """
        request = context.request
        message = make_query(
            request.qname if qname is None else qname,
            request.rdtype if rdtype is None else rdtype,
            rdclass=request.rdclass,
        )
        return cls(
            worker_id=context.worker_id,
            request=Request.from_message(
                message, request.listener, request.remote_address
            ),
            is_subquery=True,
        )
