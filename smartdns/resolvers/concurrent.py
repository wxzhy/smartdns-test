"""并发解析器：同时查询多个子解析器，按完成顺序择优并收集候选。"""

from typing import TYPE_CHECKING

from anyio import create_memory_object_stream, create_task_group, current_time
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Context, Request, Response, published_ip_infos
from smartdns.resolvers.base import BaseResolver
from smartdns.utils.components import lookup_all
from smartdns.utils.deadline import response_scope, response_timeout

if TYPE_CHECKING:
    from smartdns.actions.manager import ActionManager
    from smartdns.models.resolver import ConcurrentResolverConfig
    from smartdns.resolvers.manager import ResolverManager


class ConcurrentResolver(BaseResolver):
    """并发查询直接上游，并按完成顺序选择和收集候选。"""

    def __init__(
        self,
        config: ConcurrentResolverConfig,
        resolvers: ResolverManager,
        actions: ActionManager,
    ) -> None:
        super().__init__(config)
        self._upstream_names = config.resolvers
        self._manager = resolvers
        self._wait_all = config.wait_all
        self._nodata_grace = config.nodata_grace
        self._actions = lookup_all(actions, config.actions)

    async def start(self) -> None:
        logger.info(
            "ConcurrentResolver {} 已启动，上游={}，wait_all={}",
            self.name,
            self._upstream_names,
            self._wait_all,
        )

    async def stop(self) -> None:
        logger.info("ConcurrentResolver {} 已停止", self.name)

    def _resolve_upstreams(self) -> list[BaseResolver]:
        return lookup_all(self._manager, self._upstream_names)

    async def _run_actions(self, context: Context, candidate: Response) -> None:
        if candidate.rcode == Rcode.NOERROR and candidate.ans is not None:
            for action in self._actions:
                await action.on_resolver(context, candidate)
                if candidate.invalid:
                    break

    async def _query_upstream(
        self,
        resolver: BaseResolver,
        request: Request,
        context: Context | None,
    ) -> tuple[Response | None, Context | None]:
        """在分支内完成查询与本层检查，返回尚未发布的完整结果。"""
        child_context = (
            Context(
                worker_id=context.worker_id,
                request=request,
                is_subquery=True,
                ext=dict(context.ext),
            )
            if context is not None
            else None
        )
        try:
            result = await resolver.query(request, child_context)
            if child_context is not None:
                if result.invalid:
                    return result, None
                await self._run_actions(child_context, result)
                if result.invalid:
                    # 胜者被本层拒绝时，整个嵌套分支不得向父上下文发布。
                    return result, None
                checked = {id(result)}
                validated: dict[str, Response] = {}
                if child_context.candidates:
                    ready = result.rcode == Rcode.NXDOMAIN or (
                        result.rcode == Rcode.NOERROR and result.ans is not None
                    )
                    # 已通过检查的胜者不应因其他候选的后处理超时而丢失。
                    # 本地软范围提前结束，给父级消费结果与回包留出预算。
                    with response_scope(
                        request, response_timeout(request), response_ready=ready
                    ):
                        for name, candidate in child_context.candidates.items():
                            if candidate.invalid:
                                continue
                            if id(candidate) not in checked:
                                await self._run_actions(child_context, candidate)
                                checked.add(id(candidate))
                            if not candidate.invalid:
                                validated[name] = candidate
                child_context.candidates = validated
            return result, child_context
        except Exception:
            logger.warning(
                "ConcurrentResolver {} 的上游 {} 查询失败",
                self.name,
                resolver.name,
            )
            return None, None

    @staticmethod
    def _merge_child_results(context: Context, child: Context) -> None:
        """把嵌套解析器写入子上下文的候选与测速结果合并回父上下文。

        子上下文按上游名索引候选、按 IP 索引测速结果，同键后写覆盖；
        外层动作（speedcheck 择优等）因此能看见内层已收集的数据。
        """
        context.candidates.update(child.candidates)
        context.ip_infos.update(published_ip_infos(child.candidates, child.ip_infos))

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """在总超时内返回最快成功应答，并保留所有已完成候选。

        带记录的 NOERROR 优先；NODATA 次之（wait_all=false 时只再等待
        nodata_grace），然后是 NXDOMAIN，最后回退其他否定响应。
        """
        resolvers = self._resolve_upstreams()
        if not resolvers:
            return Response.servfail(self.name)

        candidates: dict[str, Response] = {}
        winner: Response | None = None
        # NOERROR 但无记录（NODATA）：可作为结果返回，但不抢先于带记录的应答。
        nodata: Response | None = None
        send, receive = create_memory_object_stream[
            tuple[Response | None, Context | None]
        ](len(resolvers))

        async def run(resolver: BaseResolver) -> None:
            result = await self._query_upstream(resolver, request, context)
            await send.send(result)

        with response_scope(request, self.timeout) as scope:
            async with create_task_group() as tg:
                for resolver in resolvers:
                    tg.start_soon(run, resolver)
                for _ in resolvers:
                    result, child_context = await receive.receive()
                    if result is None or result.invalid:
                        continue
                    candidates[result.upstream] = result
                    if context is not None and child_context is not None:
                        # 只有本层已完整消费的分支才发布候选和测速信息。
                        child_context.candidates[result.upstream] = result
                        self._merge_child_results(context, child_context)
                    if result.rcode == Rcode.NOERROR and result.ans is not None:
                        if result.ans.rrset is None:
                            if nodata is None:
                                nodata = result
                                scope.response_ready()
                                if not self._wait_all:
                                    # 有界宽限：一致的上游通常相差不多，黑洞上游
                                    # 也只让 NODATA 多等 nodata_grace。
                                    tg.cancel_scope.deadline = min(
                                        tg.cancel_scope.deadline,
                                        current_time() + self._nodata_grace,
                                    )
                        elif winner is None:
                            winner = result
                            scope.response_ready()
                            if not self._wait_all:
                                tg.cancel_scope.cancel()
                                break
                    elif result.rcode == Rcode.NXDOMAIN:
                        scope.response_ready()

        await send.aclose()
        await receive.aclose()
        if context is not None:
            context.candidates.update(candidates)
        result = self._pick(winner, nodata, candidates)
        logger.debug(
            "ConcurrentResolver {}：{} 选用 {}（rcode={}，候选: {}）",
            self.name,
            request.qname,
            result.upstream,
            result.rcode.name,
            list(candidates),
        )
        return result

    def _pick(
        self,
        winner: Response | None,
        nodata: Response | None,
        candidates: dict[str, Response],
    ) -> Response:
        """优先级：带记录的 NOERROR > NODATA > NXDOMAIN > 其他否定响应。"""
        if winner is not None:
            return winner
        if nodata is not None:
            return nodata
        for candidate in candidates.values():
            if candidate.rcode == Rcode.NXDOMAIN:
                return candidate
        if candidates:
            return next(iter(candidates.values()))
        return Response.servfail(self.name)
