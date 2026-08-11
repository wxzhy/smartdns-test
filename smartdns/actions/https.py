from typing import TYPE_CHECKING

from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import ALPNParam, ECHParam, ParamKey
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import check_ech, process_https_record
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context, match_response

if TYPE_CHECKING:
    from smartdns.models.action import HTTPSActionConfig
    from smartdns.models.context import Context, Request, Response
    from smartdns.nameservers.client import HTTPClient


class HTTPSAction(BaseAction):
    """HTTPS 应答处理：移除 hint/h3，并按标签为匹配的记录添加 ECH。"""

    def __init__(self, config: HTTPSActionConfig, client: HTTPClient):
        super().__init__(config)
        self._match_name = config.match_name
        self._match_name.query_types = {"HTTPS"}
        self._match_ip = config.match_ip
        self._add_ech = config.add_ech
        self._remove_hint = config.remove_hint
        self._remove_h3 = config.remove_h3
        self._ech_domain = config.ech_domain
        self._client = client

    async def start(self) -> None:
        logger.info(
            f"启动HTTPS操作 {self.name}，add_ech={self._add_ech} "
            f"remove_hint={self._remove_hint} remove_h3={self._remove_h3}"
        )

    async def on_response(self, context: Context) -> None:
        request, response = context.request, context.response
        if response is None or response.ans is None or response.ans.rrset is None:
            return
        # 跳过类型不匹配的
        if response.rcode != Rcode.NOERROR or response.ans.rdtype != RdataType.HTTPS:
            return
        # 执行ALPN和HINT操作
        process_https_record(context, self._remove_hint, self._remove_h3)
        if not match_context(self._match_name, context):
            logger.debug(f"HTTPS操作跳过不匹配的域名: {request.qname}")
            return
        if not match_response(self._match_ip, response):
            logger.debug(f"HTTPS操作跳过不匹配的标签: {request.qname}")
            return

        # 跳过已有ECH的
        if check_ech(context):
            logger.debug(f"HTTPS操作跳过已有ECH的: {request.qname}")
            return
        # 匹配
        if self.match_context(context):
            await self.add_ech(context)

    def match_context(self, context: Context) -> bool:
        """匹配请求上下文，返回是否匹配。"""
        request = context.request
        response = context.response
        if response is None or response.ans is None:
            return False
        if not match_context(self._match_name, context):
            logger.debug(f"HTTPS操作跳过不匹配的域名: {request.qname}")
            return False
        if not match_response(self._match_ip, response):
            logger.debug(f"HTTPS操作跳过不匹配的标签: {request.qname}")
            return False
        return True

    async def add_ech(self, context: Context) -> None:
        """为匹配的HTTPS记录添加ECH参数。"""
        request, response = context.request, context.response
        if response is None or response.ans is None:
            return
        try:
            # 获取ECH密钥
            ech_key = await self._client.get_ech_key(self._ech_domain)
            logger.debug(
                f"HTTPS操作获取ECH密钥: {request.qname} {request.rdtype}，ECH密钥: {ech_key}"
            )
            if ech_key is not None:
                value = ech_key
                logger.debug(
                    f"HTTPS操作成功添加ECH: {request.qname} {request.rdtype}，ECH密钥: {ech_key}"
                )
            else:
                logger.warning(
                    f"HTTPS操作未能获取到ECH密钥: {request.qname} {request.rdtype}"
                )
                return
        except Exception as e:
            logger.error(
                f"HTTPS操作获取ECH密钥失败: {request.qname} {request.rdtype}，错误: {e}"
            )
            return
        if response.ans.rrset is not None:
            for rr in response.ans.rrset:
                if not isinstance(rr, HTTPS):
                    continue
                rr.params._odict[ParamKey.ECH] = ECHParam.from_value(value)
                logger.debug(
                    f"HTTPS操作为记录添加ECH参数: {request.qname} {request.rdtype}，ECH密钥: {value}"
                )
        else:
            logger.warning(
                f"HTTPS操作未能为记录添加ECH参数: {request.qname} {request.rdtype}，因为没有找到HTTPS记录"
            )
