from typing import TYPE_CHECKING, cast

from dns.message import QueryMessage, make_query, make_response
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.resolver import Answer
from dns.rrset import RRset
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.context import Context, Response

if TYPE_CHECKING:
    from smartdns.models.action import StaticActionConfig


class StaticAction(BaseAction):
    """静态返回 Action：before 阶段直接以配置的静态 IP 应答并停止后续处理。"""

    def __init__(self, config: StaticActionConfig):
        super().__init__(config)
        self.ipv4 = config.ipv4
        self.ipv6 = config.ipv6

    async def start(self) -> None:
        logger.info(f"启动静态返回 Action: {self.name}")

    async def on_request(self, context: Context) -> None:
        request = context.request
        name, rdclass, rdtype = request.qname, request.rdclass, request.rdtype
        message = make_response(
            make_query(name, rdtype, rdclass, use_edns=True, payload=1232), True, 1232
        )
        rrset = RRset(name, rdclass, rdtype)
        rrset.update_ttl(86400)
        if self.ipv4 and rdtype == RdataType.A:
            for ip in self.ipv4:
                rrset.add(A(rdclass, rdtype, ip))
        elif self.ipv6 and rdtype == RdataType.AAAA:
            for ip in self.ipv6:
                rrset.add(AAAA(rdclass, rdtype, ip))
        else:
            logger.debug(f"静态返回 Action {self.name} 不匹配请求类型 {rdtype}")
        if rrset:
            message.answer.append(rrset)
        answer = Answer(name, rdtype, rdclass, cast("QueryMessage", message))
        context.response = Response.from_answer(answer, upstream=self.name)
        # 静态应答后立即停止后续处理。
        context.stop = True
