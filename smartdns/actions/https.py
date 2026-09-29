from time import time
from typing import TYPE_CHECKING, cast

from dns.message import make_response
from dns.name import root
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import ALPNParam, ECHParam, ParamKey
from dns.resolver import Answer
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import append_answer_rrset, replace_answer_rrset
from smartdns.actions.base import BaseAction
from smartdns.models.context import Context, Response
from smartdns.routing.matcher import match_context, match_response

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.models.action import HTTPSActionConfig
    from smartdns.nameservers.client import HTTPClient


_SYNTHETIC_HTTPS_MAX_TTL = 300


class HTTPSAction(BaseAction):
    """以 copy-on-write 清理 HTTPS 参数并按需注入 ECH。

    match_ip 依据 HTTPS 记录 hint 派生的 IP 标签判定；记录无 hint 且
    启用 subquery 且 match_ip 配置了条件时，on_response 设置 A 记录子查询，在
    on_subquery 阶段用应答 IP 的标签完成判定后统一清理与注入。
    启用 subquery 时，HTTPS NODATA 也通过 A 查询判定，命中且取得 ECH 时合成记录。
    """

    def __init__(self, config: HTTPSActionConfig, client: HTTPClient) -> None:
        super().__init__(config)
        self._match_name = config.match_name.model_copy(deep=True)
        self._match_name.query_types = {"HTTPS"}
        self._match_ip = config.match_ip
        # match_ip 是否配置了判定条件；无条件时判定恒定，缺标签也无需子查询。
        self._match_ip_needs_tags = (
            config.match_ip.ip_include is not None
            or config.match_ip.ip_exclude is not None
            or config.match_ip.asn_include is not None
            or config.match_ip.asn_exclude is not None
        )
        self._add_ech = config.add_ech
        self._enable_subquery = config.enable_subquery
        self._remove_hint = config.remove_hint
        self._remove_h3 = config.remove_h3
        self._ech_domain = config.ech_domain
        self._client = client
        # on_response 与 on_subquery 之间经 context.ext 传递的挂起标记。
        self._pending_key = f"{self.name}:ech-pending"

    async def start(self) -> None:
        logger.info("HTTPS Action {} 已启动", self.name)

    async def on_response(self, context: Context) -> None:
        logger.debug(
            "HTTPS Action {} on_response: {}",
            self.name,
            context.request.qname,
        )
        response = context.response
        if (
            response is None
            or response.rcode != Rcode.NOERROR
            or context.request.rdtype != RdataType.HTTPS
            or (response.ans is not None and response.ans.rdtype != RdataType.HTTPS)
        ):
            logger.debug(
                "HTTPS Action {} on_response: {} -> 无效应答，跳过",
                self.name,
                context.request.qname,
            )
            return
        logger.debug(
            "HTTPS Action {} on_response: {} -> {}",
            self.name,
            context.request.qname,
            response.ans,
        )
        if self._try_defer_ech(context, response):
            return
        if response.ans is None or response.ans.rrset is None:
            return
        ech_value = await self._resolve_ech_value(response, context)
        self._rebuild(context, response, response.ans.rrset, ech_value)

    async def on_subquery(self, context: Context, response: Response) -> None:
        """A 记录子查询返回后，用其 IP 标签完成 match_ip 判定并统一重写。

        response 的 ip_infos 已按 GeoIP/IPSet 打标；无有效 A 记录时不注入
        ECH，已有 HTTPS 记录仍执行参数清理。
        """
        if not context.ext.pop(self._pending_key, False):
            return
        main = context.response
        if (
            main is None
            or main.rcode != Rcode.NOERROR
            or context.request.rdtype != RdataType.HTTPS
            or (main.ans is not None and main.ans.rdtype != RdataType.HTTPS)
        ):
            return
        ech_value: str | None = None
        if (
            self._add_ech
            and self._client is not None
            and response.rcode == Rcode.NOERROR
            and response.ans is not None
            and response.ans.rdtype == RdataType.A
            and response.ans.rrset is not None
            and response.ip_infos
            and match_response(self._match_ip, response)
        ):
            ech_value = await self._fetch_ech_value()
        logger.debug(
            "HTTPS Action {} on_subquery: {} -> {} (ech_value={})",
            self.name,
            context.request.qname,
            main.ans,
            ech_value,
        )
        if main.ans is None or main.ans.rrset is None:
            if ech_value is not None:
                self._synthesize_https(context, main, response, ech_value)
            return
        self._rebuild(context, main, main.ans.rrset, ech_value)

    def _try_defer_ech(self, context: Context, response: Response) -> bool:
        """无 hint 或 HTTPS NODATA 时设置 A 子查询，把处理延迟到 on_subquery。

        有 HTTPS 记录时，match_ip 配置了条件才需要标签；NODATA 即使
        match_ip 无条件，也必须确认 A 记录存在。子查询槽位不被覆盖。
        """
        has_rrset = response.ans is not None and response.ans.rrset is not None
        if (
            not self._enable_subquery
            or not self._add_ech
            or self._client is None
            or context.subquery is not None
            or not match_context(self._match_name, context)
            or (has_rrset and (not self._match_ip_needs_tags or response.ip_infos))
        ):
            return False
        context.subquery = Context.for_subquery(context, rdtype=RdataType.A)
        context.ext[self._pending_key] = True
        return True

    async def _resolve_ech_value(
        self, response: Response, context: Context
    ) -> str | None:
        if (
            not self._add_ech
            or not match_context(self._match_name, context)
            or (self._match_ip_needs_tags and not response.ip_infos)
            or not match_response(self._match_ip, response)
            or self._client is None
        ):
            return None
        return await self._fetch_ech_value()

    async def _fetch_ech_value(self) -> str | None:
        if self._client is None:
            return None
        try:
            value = await self._client.get_ech_key(self._ech_domain)
        except Exception:
            logger.warning("HTTPS Action {} 获取 ECH 失败", self.name)
            return None
        if value is None:
            logger.warning("HTTPS Action {} 未获取到 ECH", self.name)
        return value.strip('"') if value is not None else None

    def _rebuild(
        self,
        context: Context,
        response: Response,
        old_rrset: RRset,
        ech_value: str | None,
    ) -> None:
        """copy-on-write 重建主应答 RRset；有变化才替换 context.response。"""
        new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
        new_rrset.update_ttl(old_rrset.ttl)
        changed = False
        for rr in old_rrset:
            rewritten, item_changed = self._rewrite_https(rr, ech_value)
            new_rrset.add(rewritten)
            changed = changed or item_changed
        if changed:
            context.response = replace_answer_rrset(response, new_rrset)

    def _synthesize_https(
        self,
        context: Context,
        main: Response,
        sub_response: Response,
        ech_value: str,
    ) -> None:
        """仅在 A 子查询命中时，把 HTTPS NODATA 变成短 TTL 的 ECH 记录。"""
        if main.ans is None:
            message = make_response(context.request.msg, True, our_payload=1232, pad=0)
            answer = Answer(
                context.request.qname,
                RdataType.HTTPS,
                context.request.rdclass,
                cast("QueryMessage", message),
            )
            main = Response.from_answer(answer, upstream=main.upstream)
        answer = main.ans
        sub_answer = sub_response.ans
        assert answer is not None
        assert sub_answer is not None
        assert sub_answer.rrset is not None
        now = time()
        ttl = min(
            _SYNTHETIC_HTTPS_MAX_TTL,
            sub_answer.rrset.ttl,
            max(0, int(sub_answer.expiration - now)),
            max(0, int(answer.expiration - now)),
        )
        rrset = RRset(answer.canonical_name, answer.rdclass, RdataType.HTTPS)
        rrset.update_ttl(ttl)
        rrset.add(
            HTTPS(
                answer.rdclass,
                RdataType.HTTPS,
                1,
                root,
                {ParamKey.ECH: ECHParam.from_value(ech_value)},
            )
        )
        context.response = append_answer_rrset(main, rrset, remove_negative_soa=True)

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
