from typing import TYPE_CHECKING

from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import ALPNParam, ECHParam, ParamKey
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import replace_answer_rrset
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context, match_response

if TYPE_CHECKING:
    from smartdns.models.action import HTTPSActionConfig
    from smartdns.models.context import Context, Request, Response
    from smartdns.nameservers.client import HTTPClient


class HTTPSAction(BaseAction):
    """以 copy-on-write 清理 HTTPS 参数并按需注入 ECH。"""

    def __init__(self, config: HTTPSActionConfig, client: HTTPClient) -> None:
        super().__init__(config)
        self._match_name = config.match_name.model_copy(deep=True)
        self._match_name.query_types = {"HTTPS"}
        self._match_ip = config.match_ip
        self._add_ech = config.add_ech
        self._remove_hint = config.remove_hint
        self._remove_h3 = config.remove_h3
        self._ech_domain = config.ech_domain
        self._client = client

    async def start(self) -> None:
        logger.info("HTTPS Action {} 已启动", self.name)

    async def on_response(self, context: Context) -> None:
        response = context.response
        if (
            response is None
            or response.ans is None
            or response.ans.rrset is None
            or response.rcode != Rcode.NOERROR
            or response.ans.rdtype != RdataType.HTTPS
        ):
            return
        ech_value = await self._resolve_ech_value(context.request, response, context)
        old_rrset = response.ans.rrset
        new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
        new_rrset.update_ttl(old_rrset.ttl)
        changed = False
        for rr in old_rrset:
            rewritten, item_changed = self._rewrite_https(rr, ech_value)
            new_rrset.add(rewritten)
            changed = changed or item_changed
        if changed:
            context.response = replace_answer_rrset(response, new_rrset)

    async def _resolve_ech_value(
        self, request: Request, response: Response, context: Context
    ) -> str | None:
        if (
            not self._add_ech
            or not match_context(self._match_name, context)
            or not match_response(self._match_ip, response)
            or self._client is None
        ):
            return None
        try:
            value = await self._client.get_ech_key(self._ech_domain)
        except Exception:
            logger.warning("HTTPS Action {} 获取 ECH 失败", self.name)
            return None
        if value is None:
            logger.warning("HTTPS Action {} 未获取到 ECH", self.name)
        return value.strip('"') if value is not None else None

    def _rewrite_https(self, rr: HTTPS, ech_value: str | None) -> tuple[HTTPS, bool]:
        params = dict(rr.params)
        changed = False
        if self._remove_hint:
            changed = params.pop(ParamKey.IPV4HINT, None) is not None or changed
            changed = params.pop(ParamKey.IPV6HINT, None) is not None or changed
        if self._remove_h3 and ParamKey.ALPN in params:
            ids = tuple(item for item in params[ParamKey.ALPN].ids if item != b"h3")
            if ids != params[ParamKey.ALPN].ids:
                changed = True
                if ids:
                    params[ParamKey.ALPN] = ALPNParam(ids=ids)
                else:
                    del params[ParamKey.ALPN]
        if ech_value is not None and ParamKey.ECH not in params:
            params[ParamKey.ECH] = ECHParam.from_value(ech_value)
            changed = True
        if not changed:
            return rr, False
        return HTTPS(rr.rdclass, rr.rdtype, rr.priority, rr.target, params), True
