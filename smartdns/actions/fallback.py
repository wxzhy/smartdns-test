from __future__ import annotations

from asyncio import as_completed
from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._ping import speedtest
from smartdns.actions.base import BaseAction

if TYPE_CHECKING:
    from pydantic.networks import IPvAnyAddress

    from smartdns.models.action import (
        FallbackActionConfig,
        FallbackMap,
        PingConfig,
    )
    from smartdns.models.context import Context


class FallbackAction(BaseAction):
    """Fallback Action：命中标签的应答 IP 若测速全失败，则回退到静态 IP 列表。"""

    def __init__(self, config: FallbackActionConfig):
        super().__init__(config)
        self.exclude = config.exclude
        self.map: list[FallbackMap] = config.map
        self.speedtest_config = config.speedtest

    async def start(self) -> None:
        logger.info(f"启动 Fallback Action {self.name}，映射数: {len(self.map)}")

    async def on_response(self, context: Context) -> None:
        pass

    #     request, response = context.request, context.response
    #     if response is None or response.ans is None or response.ans.rrset is None:
    #         return
    #     if request.rdtype not in (RdataType.A, RdataType.AAAA):
    #         return
    #     if response.rcode != Rcode.NOERROR:
    #         return
    #     if is_excluded(request, response, self.exclude):
    #         logger.debug(f"Fallback Action 跳过排除域名: {request.qname}")
    #         return
    #     if response.ip_infos is None:
    #         return
    #     # 并发测速全部应答 IP；异常降级为 None，不让任务组崩溃。
    #     results = await self._speedtest_all(response.ip_infos)
    #     for item in self.map:
    #         if not is_included(request, response, item.domain_include):
    #             continue
    #         matched = [
    #             info
    #             for info in response.ip_infos
    #             if info.country is not None and item.ip_include & info.country
    #         ]
    #         if not matched:
    #             continue
    #         # 命中项全部测速失败 -> 用静态 IP 替换应答 rrset。
    #         if all(results.get(info.ip) is None for info in matched):
    #             new_rrset = self._build_static_rrset(
    #                 request.rdtype, response.ans.rrset, item
    #             )
    #             if new_rrset is not None:
    #                 logger.debug(
    #                     f"Fallback Action {self.name} 命中且测速全失败，"
    #                     f"替换为静态 IP: {item.ipv4 or item.ipv6}"
    #                 )
    #                 context.response = replace_answer_rrset(
    #                     response, new_rrset, self.name
    #                 )
    #                 return
    #
    # async def _speedtest_all(self, ip_infos: list) -> dict[IPvAnyAddress, float | None]:
    #     """并发测速全部 IP，返回 ip→延迟映射，失败或异常记为 None。"""
    #
    #     async def _tag(
    #         ip: IPvAnyAddress, config: SpeedtestConfig
    #     ) -> tuple[IPvAnyAddress, float | None]:
    #         try:
    #             return ip, await speedtest(ip, config)
    #         except Exception:
    #             logger.exception(f"测速异常: {ip}")
    #             return ip, None
    #
    #     results: dict[IPvAnyAddress, float | None] = {}
    #     async with create_task_group() as tg:
    #         handles = [
    #             tg.start_soon(_tag, info.ip, self.speedtest_config) for info in ip_infos
    #         ]
    #         for handle in as_completed(handles):
    #             ip, result = await handle
    #             results[ip] = result
    #     return results
    #
    # def _build_static_rrset(
    #     self, rdtype: RdataType, old_rrset: RRset, item: FallbackMap
    # ) -> RRset | None:
    #     """构造静态 IP 列表的新 rrset；无对应类型静态地址则返回 None。"""
    #     new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
    #     new_rrset.update_ttl(old_rrset.ttl)
    #     if rdtype == RdataType.A:
    #         if item.ipv4 is None:
    #             return None
    #         for address in item.ipv4:
    #             new_rrset.add(A(old_rrset.rdclass, old_rrset.rdtype, str(address)))
    #     else:
    #         if item.ipv6 is None:
    #             return None
    #         for address in item.ipv6:
    #             new_rrset.add(AAAA(old_rrset.rdclass, old_rrset.rdtype, str(address)))
    #     if len(new_rrset) == 0:
    #         return None
    #     return new_rrset
