from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ALPNParam, ECHParam, ParamKey
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import HTTPSActionConfig
from smartdns.models.context import Context
from smartdns.nameservers.client import HTTPClient


class HTTPSAction(BaseAction):
    """HTTPS操作类，用于处理HTTPS相关的操作。"""

    def __init__(self, config: HTTPSActionConfig, client: HTTPClient):
        super().__init__(config)
        self.exclude = config.exclude
        self.tags: set[str] = config.tag
        self._add_ech = config.add_ech
        self._remove_hint = config.remove_hint
        self._remove_h3 = config.remove_h3
        self._ech_domain = config.ech_domain
        self._client = client

    async def start(self):
        """初始化操作"""
        logger.info(
            f"初始化HTTPS操作，添加ECH: {self._add_ech}, 移除Hint: {self._remove_hint}, 移除H3: {self._remove_h3}, 排除域名: {self.exclude}, 标签: {self.tags}"
        )

    async def on_response(self, context: Context):
        """处理HTTPS相关的响应"""
        logger.debug(f"HTTPSAction {self.name} on_response: {context.response}")
        request, response = context.request, context.response
        if response is None:
            return
        # 排除非HTTPS记录的响应
        if request.rdtype != RdataType.HTTPS:
            logger.debug(
                f"HTTPS操作跳过非HTTPS记录的响应: {request.qname} {request.rdtype}"
            )
            return
        if response.rcode != Rcode.NOERROR or response.ans is None:
            logger.debug(
                f"HTTPS操作跳过非NOERROR响应: {request.qname} {request.rdtype} {response.rcode}"
            )
            return
        logger.debug(
            f"HTTPSAction {self.name} 处理响应: {request.qname} {request.rdtype} {response.ans.rrset}"
        )
        if response.ans.rrset is not None:
            for rr in response.ans.rrset:
                # 处理每个RR记录
                if rr.rdtype == RdataType.HTTPS:
                    # 移除Hint
                    if self._remove_hint:
                        if ParamKey.IPV4HINT in rr.params:
                            del rr.params._odict[ParamKey.IPV4HINT]
                        if ParamKey.IPV6HINT in rr.params:
                            del rr.params._odict[ParamKey.IPV6HINT]
                        logger.debug(
                            f"HTTPS操作移除Hint: {request.qname} {request.rdtype}"
                        )
                    # 移除H3
                    if self._remove_h3 and ParamKey.ALPN in rr.params:
                        ids: tuple = rr.params[ParamKey.ALPN].ids
                        new_ids = tuple(id for id in ids if id != b"h3")
                        rr.params._odict[ParamKey.ALPN] = ALPNParam(ids=new_ids)
                        logger.debug(
                            f"HTTPS操作移除H3: {request.qname} {request.rdtype}，剩余ALPN: {new_ids}"
                        )
                    # 添加ECH，跳过已有的ECH记录
                    if not self._add_ech or ParamKey.ECH in rr.params:
                        return
                    # 排除域名
                    if (
                        self.exclude is not None
                        and request.name_info.country is not None
                        and request.name_info.country & self.exclude
                    ):
                        logger.debug(
                            f"添加ECH操作跳过排除的域名: {request.qname} {request.rdtype} {request.name_info.country}"
                        )
                        return
                    # 排除CNAME
                    if response.name_infos is not None:
                        for cname in response.name_infos:
                            if (
                                self.exclude is not None
                                and cname.country is not None
                                and cname.country & self.exclude
                            ):
                                logger.debug(
                                    f"替换IP操作跳过排除的CNAME: {request.qname} {request.rdtype} {cname.country}"
                                )
                                return
                    # 匹配tag
                    if response.ip_infos is not None:
                        for ip_info in response.ip_infos:
                            if (
                                ip_info.country is not None
                                and self.tags & ip_info.country
                            ):
                                logger.debug(
                                    f"HTTPS操作添加ECH: {request.qname} {request.rdtype} {ip_info.country}"
                                )
                                try:
                                    # 获取ECH密钥
                                    ech_key = await self._client.get_ech_key(
                                        self._ech_domain
                                    )
                                    logger.debug(
                                        f"HTTPS操作获取ECH密钥: {request.qname} {request.rdtype}，ECH密钥: {ech_key}"
                                    )
                                    if ech_key is not None:
                                        value = ech_key.strip('"')
                                        rr.params._odict[ParamKey.ECH] = (
                                            ECHParam.from_value(value)
                                        )
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
