"""静态应答 Action：before 阶段直接以配置的 IP 回答并结束路由。"""

from time import time
from typing import TYPE_CHECKING, cast

from dns.message import QueryMessage, make_query
from dns.rdatatype import RdataType
from dns.resolver import Answer
from loguru import logger

from smartdns.actions._helper import address_rrset
from smartdns.actions.base import BaseAction
from smartdns.models.context import EDNS_PAYLOAD, Context, Response, reply_to

if TYPE_CHECKING:
    from smartdns.models.action import StaticActionConfig


class StaticAction(BaseAction):
    """A/AAAA 返回配置的地址，其他类型返回空 NOERROR；TTL 均为配置值。"""

    def __init__(self, config: StaticActionConfig):
        super().__init__(config)
        self.ipv4 = config.ipv4
        self.ipv6 = config.ipv6
        self.ttl = config.ttl

    async def start(self) -> None:
        logger.info(
            "启动静态返回 Action {}：IPv4={} IPv6={} TTL={}",
            self.name,
            sorted(map(str, self.ipv4)),
            sorted(map(str, self.ipv6)),
            self.ttl,
        )

    async def on_request(self, context: Context) -> None:
        request = context.request
        name, rdclass, rdtype = request.qname, request.rdclass, request.rdtype
        # 不基于客户端报文构造，避免把客户端的标志位与 EDNS 选项写进缓存条目。
        message = reply_to(
            make_query(name, rdtype, rdclass, use_edns=True, payload=EDNS_PAYLOAD)
        )
        addresses = {RdataType.A: self.ipv4, RdataType.AAAA: self.ipv6}.get(rdtype, ())
        rrset = address_rrset(name, rdclass, rdtype, self.ttl, addresses)
        if rrset is not None:
            # find_rrset(create=True) 同时维护索引，Answer 才能取到主应答。
            target = message.find_rrset(
                message.answer, name, rdclass, rdtype, create=True
            )
            target.update(rrset)
        answer = Answer(name, rdtype, rdclass, cast("QueryMessage", message))
        # 空静态应答没有 SOA，dnspython 默认使用 MAX_TTL；仍应遵守配置 TTL。
        answer.expiration = min(answer.expiration, time() + self.ttl)
        logger.debug(
            "静态返回 Action {}：{} {} -> {}",
            self.name,
            name,
            rdtype.name,
            [rr.to_text() for rr in rrset] if rrset is not None else "空应答",
        )
        context.response = Response.from_answer(answer, upstream=self.name)
        # 静态应答后立即停止后续处理。
        context.stop = True
