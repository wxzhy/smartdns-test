from typing import TYPE_CHECKING

from anyio import create_memory_object_stream, create_task_group, move_on_after
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Context, Request, Response
from smartdns.resolvers.base import BaseResolver

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
        self._actions = [actions.get(name) for name in config.actions]

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
        return [
            resolver
            for name in self._upstream_names
            if (resolver := self._manager.get(name)) is not None
        ]

    async def _query_upstream(
        self,
        resolver: BaseResolver,
        request: Request,
        context: Context | None,
    ) -> Response | None:
        """执行单个直接上游，嵌套解析器使用独立 Context。"""
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
            if result.rcode == Rcode.NOERROR and result.ans is not None:
                for action in self._actions:
                    if action is None or context is None:
                        continue
                    await action.on_resolver(context, result)
                    if result.invalid:
                        break
            return result
        except Exception:
            logger.warning(
                "ConcurrentResolver {} 的上游 {} 查询失败",
                self.name,
                resolver.name,
            )
            return None

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """在总超时内返回最快成功应答，并保留所有已完成候选。"""
        resolvers = self._resolve_upstreams()
        if not resolvers:
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

        candidates: dict[str, Response] = {}
        winner: Response | None = None
        send, receive = create_memory_object_stream[Response | None](len(resolvers))

        async def run(resolver: BaseResolver) -> None:
            result = await self._query_upstream(resolver, request, context)
            await send.send(result)

        with move_on_after(self.timeout):
            async with create_task_group() as tg:
                for resolver in resolvers:
                    tg.start_soon(run, resolver)
                for _ in resolvers:
                    result = await receive.receive()
                    if result is None or result.invalid:
                        continue
                    candidates[result.upstream] = result
                    if (
                        winner is None
                        and result.rcode == Rcode.NOERROR
                        and result.ans is not None
                    ):
                        winner = result
                        if not self._wait_all:
                            tg.cancel_scope.cancel()
                            break

        await send.aclose()
        await receive.aclose()
        if context is not None:
            if context.candidates is None:
                context.candidates = {}
            context.candidates.update(candidates)
        if winner is not None:
            return winner
        for candidate in candidates.values():
            if candidate.rcode == Rcode.NXDOMAIN:
                return candidate
        if candidates:
            return next(iter(candidates.values()))
        return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
