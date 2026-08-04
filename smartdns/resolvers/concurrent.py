from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Request, Response
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.resolvers.manager import ResolverManager


class ConcurrentResolver(BaseResolver):
    """并发解析器：向多个上游同时查询，取最快的成功应答。"""

    def __init__(self, config: ConcurrentResolverConfig, resolvers: ResolverManager):
        super().__init__(config)
        self._upstreams: list[str] = config.resolvers
        self._manager: ResolverManager = resolvers

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

    async def query(self, request: Request) -> Response:
        """并发查询所有上游，返回最快的 NOERROR 应答；否则返回最佳否定应答。"""
        resolvers = self._resolve_upstreams()
        if not resolvers:
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

        winner: Response | None = None
        negatives: list[Response] = []

        async with create_task_group() as tg:

            async def _run(resolver: BaseResolver) -> None:
                nonlocal winner
                try:
                    result = await resolver.query(request)
                except Exception:
                    logger.warning(
                        f"ConcurrentResolver {self.name} 上游 {resolver.name} 查询失败"
                    )
                    return
                if result.rcode == Rcode.NOERROR:
                    if winner is None:
                        winner = result
                        tg.cancel_scope.cancel()  # 命中成功应答，取消其余查询
                else:
                    negatives.append(result)

            for resolver in resolvers:
                tg.start_soon(_run, resolver)

        if winner is not None:
            return winner
        # 无 NOERROR：优先返回 NXDOMAIN 等权威否定应答，而非一律 SERVFAIL。
        for negative in negatives:
            if negative.rcode == Rcode.NXDOMAIN:
                return negative
        if negatives:
            return negatives[0]
        return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
