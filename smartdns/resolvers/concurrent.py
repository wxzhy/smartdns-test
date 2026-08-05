from typing import TYPE_CHECKING

from anyio import create_task_group, move_on_after
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.models.context import Context
    from smartdns.models.resolver import ConcurrentResolverConfig
    from smartdns.resolvers.manager import ResolverManager


class ConcurrentResolver(BaseResolver):
    """并发解析器：向多个上游同时查询，取最快的成功应答。"""

    def __init__(self, config: ConcurrentResolverConfig, resolvers: ResolverManager):
        super().__init__(config)
        self._upstreams: list[str] = config.resolvers
        self._manager: ResolverManager = resolvers
        self._wait_all: bool = config.wait_all

    async def start(self):
        """启动解析器。上游在 query 时按名惰性解析，避免启动顺序依赖。"""
        logger.info(
            f"ConcurrentResolver {self.name} 启动成功，上游解析器: {self._upstreams}"
        )

    async def stop(self):
        """停止解析器"""
        logger.info(f"ConcurrentResolver {self.name} 停止成功")

    def _resolve_upstreams(self) -> list[BaseResolver]:
        """按名解析上游解析器实例（查询时调用，不依赖启动顺序）。"""
        resolvers: list[BaseResolver] = []
        for name in self._upstreams:
            resolver = self._manager.get(name)
            if resolver is None:
                logger.warning(f"ConcurrentResolver {self.name} 上游 {name} 不存在")
            else:
                resolvers.append(resolver)
        return resolvers

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """并发查询所有上游，返回最快的 NOERROR 应答；否则返回最佳否定应答。

        所有收到的应答（含否定应答）按到达顺序累积进 context.candidates，供 after
        动作二次挑选；wait_all 为 True 时不提前取消其余上游，等到全部结束以收齐候选，
        应答仍取最快到达的 NOERROR。整体查询以 self.timeout 为上界。
        """
        resolvers = self._resolve_upstreams()
        if not resolvers:
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

        winner: Response | None = None
        candidates: list[Response] = []

        with move_on_after(self.timeout):
            async with create_task_group() as tg:

                async def _run(resolver: BaseResolver) -> None:
                    nonlocal winner
                    try:
                        # 不向下传 context：candidates 只记录本层直接上游的应答，
                        # 避免嵌套 concurrent 时同一结果被内外层重复写入。
                        result = await resolver.query(request)
                    except Exception:
                        logger.warning(
                            f"ConcurrentResolver {self.name} "
                            f"上游 {resolver.name} 查询失败"
                        )
                        return
                    candidates.append(result)
                    if winner is None and result.rcode == Rcode.NOERROR:
                        winner = result
                        if not self._wait_all:
                            tg.cancel_scope.cancel()  # 命中成功应答，取消其余查询

                for resolver in resolvers:
                    tg.start_soon(_run, resolver)

        if context is not None and candidates:
            if context.candidates is None:
                context.candidates = []
            context.candidates.extend(candidates)

        if winner is not None:
            return winner
        # 无 NOERROR：优先返回 NXDOMAIN 等权威否定应答，而非一律 SERVFAIL。
        for candidate in candidates:
            if candidate.rcode == Rcode.NXDOMAIN:
                return candidate
        if candidates:
            return candidates[0]
        return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
