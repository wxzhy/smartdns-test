from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import ALPNParam, ECHParam, ParamKey
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helpers import is_excluded, replace_answer_rrset
from smartdns.actions.base import BaseAction
from smartdns.models.action import HTTPSActionConfig
from smartdns.models.context import Context, Request, Response
from smartdns.nameservers.client import HTTPClient


class HTTPSAction(BaseAction):
    """HTTPS 应答处理：移除 hint/h3，并按标签为匹配的记录添加 ECH。"""

    def __init__(self, config: HTTPSActionConfig, client: HTTPClient):
        super().__init__(config)
        self.exclude = config.exclude
        self.tags: set[str] = config.tag
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
        if request.rdtype != RdataType.HTTPS:
            return
        if response.rcode != Rcode.NOERROR:
            return
        old_rrset = response.ans.rrset
        # 排除域名/标签判定与 ECH 密钥获取只做一次（与具体 rr 无关）。
        ech_value = await self._resolve_ech_value(request, response)
        new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
        new_rrset.update_ttl(old_rrset.ttl)
        changed = False
        for rr in old_rrset:
            new_rr, rr_changed = self._rewrite_https(rr, ech_value)
            new_rrset.add(new_rr)
            changed = changed or rr_changed
        if changed:
            context.response = replace_answer_rrset(response, new_rrset, self.name)

    async def _resolve_ech_value(
        self, request: Request, response: Response
    ) -> str | None:
        """按排除与标签判定是否添加 ECH，并返回其值（否则 None）。"""
        if not self._add_ech:
            return None
        if is_excluded(request, response, self.exclude):
            return None
        if not self._tag_matches(response):
            return None
        ech_key = await self._client.get_ech_key(self._ech_domain)
        if ech_key is None:
            logger.warning(f"HTTPS操作未能获取ECH密钥: {self._ech_domain}")
            return None
        return ech_key.strip('"')

    def _tag_matches(self, response: Response) -> bool:
        if response.ip_infos is None:
            return False
        return any(
            ip.country is not None and self.tags & ip.country
            for ip in response.ip_infos
        )

    def _rewrite_https(self, rr: HTTPS, ech_value: str | None) -> tuple[HTTPS, bool]:
        """按配置重建单条 HTTPS rdata（copy-on-write，不改原不可变 rdata）。"""
        params = dict(rr.params)
        changed = False
        if self._remove_hint:
            if params.pop(ParamKey.IPV4HINT, None) is not None:
                changed = True
            if params.pop(ParamKey.IPV6HINT, None) is not None:
                changed = True
        if self._remove_h3 and ParamKey.ALPN in params:
            old_ids = params[ParamKey.ALPN].ids
            new_ids = tuple(i for i in old_ids if i != b"h3")
            if new_ids != old_ids:
                changed = True
                if new_ids:
                    params[ParamKey.ALPN] = ALPNParam(ids=new_ids)
                else:
                    # 唯一 ALPN 为 h3：移除整个 ALPN 参数而非留空 ids。
                    del params[ParamKey.ALPN]
        if ech_value is not None and ParamKey.ECH not in params:
            params[ParamKey.ECH] = ECHParam.from_value(ech_value)
            changed = True
        if not changed:
            return rr, False
        return HTTPS(rr.rdclass, rr.rdtype, rr.priority, rr.target, params), True
