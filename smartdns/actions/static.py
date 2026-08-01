from typing import cast

from dns.message import QueryMessage, make_query, make_response
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.resolver import Answer
from dns.rrset import RRset
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import StaticActionConfig
from smartdns.models.context import Context, Response


class StaticAction(BaseAction):
    """静态返回 Action。"""

    def __init__(self, config: StaticActionConfig):
        super().__init__(config)
        self.ipv4 = config.ipv4
        self.ipv6 = config.ipv6
        logger.info(f"初始化静态返回 Action: {self.config.name}")

    async def start(self):
        logger.info(f"启动静态返回 Action: {self.config.name}")

    async def on_request(self, context: Context):
        """在处理请求时，转发到resolver之前调用"""
        # 生成querymessage
        name, rdclass, rdtype = (
            context.request.qname,
            context.request.rdclass,
            context.request.rdtype,
        )
        message = make_query(
            name,
            rdtype,
            rdclass,
            use_edns=True,
            payload=1232,
        )
        message.set_rcode(Rcode.NOERROR)
        message = make_response(message, True, 1232)
        rrset: RRset = RRset(name, rdclass, rdtype)
        rrset.update_ttl(86400)
        if self.ipv4 and context.request.rdtype == RdataType.A:
            for ip in self.ipv4:
                rrset.add(A(rdclass, rdtype, ip))
            logger.debug(f"静态返回 Action {self.config.name} 返回 IPv4: {self.ipv4}")
        elif self.ipv6 and context.request.rdtype == RdataType.AAAA:
            for ip in self.ipv6:
                rrset.add(AAAA(rdclass, rdtype, ip))
            logger.debug(f"静态返回 Action {self.config.name} 返回 IPv6: {self.ipv6}")
        else:
            logger.debug(
                f"静态返回 Action {self.config.name} 不匹配请求类型 {context.request.rdtype}"
            )
        if rrset:
            message.answer.append(rrset)
        message = cast("QueryMessage", message)
        answer = Answer(name, rdtype, rdclass, message)
        context.response = Response.from_answer(answer, upstream=self.config.name)
        # 立刻返回
        context.stop = True
