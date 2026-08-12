from asyncio import as_completed
from typing import TYPE_CHECKING

from anyio import create_task_group, move_on_after
from dns.rcode import Rcode
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.actions.manager import ActionManager
from smartdns.models.context import Request, Response
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.models.context import Context
    from smartdns.models.resolver import ConcurrentResolverConfig
    from smartdns.resolvers.manager import ResolverManager


class ConcurrentResolver(BaseResolver):
    """并发解析器：向多个上游同时查询，取最快的成功应答。"""

    def __init__(
        self,
        config: ConcurrentResolverConfig,
        resolvers: ResolverManager,
        actions: ActionManager,
    ):
        super().__init__(config)
        self.config: ConcurrentResolverConfig = config
        self._upstreams: list[str] = config.resolvers
        self._manager: ResolverManager = resolvers
        self._wait_all: bool = config.wait_all
        self._actions: ActionManager = actions
        self.resolvers = self._resolve_upstreams()
        self.actions = self._resolve_actions()

    async def start(self):
        """启动解析器"""
        logger.info(
            f"ConcurrentResolver {self.name} 启动成功，上游解析器: {self._upstreams}，动作: {self.actions}，wait_all: {self._wait_all}"
        )

    async def stop(self):
        """停止解析器"""
        logger.info(f"ConcurrentResolver {self.name} 停止成功")

    def _resolve_upstreams(self) -> list[BaseResolver]:
        """按名解析上游解析器实例。"""
        resolvers: list[BaseResolver] = []
        for name in self._upstreams:
            resolver = self._manager.get(name)
            if resolver is None:
                logger.warning(f"ConcurrentResolver {self.name} 上游 {name} 不存在")
            else:
                resolvers.append(resolver)
        return resolvers

    def _resolve_actions(self) -> list[BaseAction] | None:
        """按名解析动作实例。"""
        if self.config.actions is None:
            return None
        actions: list[BaseAction] = []
        for name in self.config.actions:
            action = self._actions.get(name)
            if action is None:
                logger.warning(f"ConcurrentResolver {self.name} 动作 {name} 不存在")
            else:
                actions.append(action)
        return actions

    async def _run(
        self, resolver: BaseResolver, request: Request, context: Context | None = None
    ) -> Response | None:
        try:
            # 不向下传 context：candidates 只记录本层直接上游的应答，
            # 避免嵌套 concurrent 时同一结果被内外层重复写入。
            result = await resolver.query(request, context)
            # 跳过异常的结果
            if result.rcode != Rcode.NOERROR or result.ans is None:
                logger.debug(
                    f"ConcurrentResolver {self.name} 上游 {resolver.name} 返回异常应答: {result.rcode}"
                )
                return result
            logger.debug(
                f"收到 ConcurrentResolver {self.name} 上游 {resolver.name} 的应答"
            )
            # 执行actions的on_resolver阶段
            if self.actions is not None and context is not None:
                for action in self.actions:
                    logger.debug(
                        f"ConcurrentResolver {self.name} 上游 {resolver.name} 应答交给动作 {action.name} 处理"
                    )
                    await action.on_resolver(context, result)
                    if result.invalid:
                        logger.debug(
                            f"ConcurrentResolver {self.name} 上游 {resolver.name} 应答被动作 {action.name} 标记为无效"
                        )
                        break
                logger.debug(
                    f"ConcurrentResolver {self.name} 上游 {resolver.name} 应答处理完成，结果: {result.rcode}"
                )
                return result
        except Exception as e:
            logger.exception(
                f"ConcurrentResolver {self.name} 上游 {resolver.name} 查询失败: {e}"
            )
            return None

    async def query(self, request: Request, context: Context | None = None) -> Response:
        """并发查询所有上游，返回最快的 NOERROR 应答；否则返回最佳否定应答。

        所有收到的应答（含否定应答）按到达顺序累积进 context.candidates，供 after
        动作二次挑选；wait_all 为 True 时不提前取消其余上游，等到全部结束以收齐候选，
        应答仍取最快到达的 NOERROR。整体查询以 self.timeout 为上界。
        """
        if not self.resolvers:
            logger.warning(f"ConcurrentResolver {self.name} 没有可用上游解析器")
            return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)

        winner: Response | None = None
        logger.debug(
            f"ConcurrentResolver {self.name} 开始并发查询 {request.qname} Context: {context}"
        )
        candidates: dict[str, Response] = {}
        with move_on_after(self.timeout):
            async with create_task_group() as tg:
                tasks = [
                    tg.start_soon(self._run, resolver, request, context)
                    for resolver in self.resolvers
                ]
            for task in as_completed(tasks):
                result = await task
                # 收到正常结果
                if result is None or result.invalid:
                    continue
                # 选取最快的 NOERROR 应答为 winner，其他应答累积进 candidates
                if winner is None and result.rcode == Rcode.NOERROR:
                    winner = result
                candidates[result.upstream] = result
                # 等待全部上游完成或取消其余上游
                if not self._wait_all:
                    tg.cancel_scope.cancel()
        logger.debug(
            f"ConcurrentResolver {self.name} 并发查询 {request.qname} 完成，winner: {winner}, candidates: {list(candidates.keys())}"
        )
        if context is not None:
            if context.candidates is None:
                context.candidates = {}
            context.candidates.update(candidates)
        logger.debug(
            f"ConcurrentResolver {self.name} 并发查询 {request.qname} 完成，未收到 NOERROR，应答候选: {list(candidates.keys())}"
        )
        if winner is not None:
            return winner
        # 无 NOERROR：优先返回 NXDOMAIN 等权威否定应答，而非一律 SERVFAIL。
        for candidate in candidates.values():
            if candidate.rcode == Rcode.NXDOMAIN:
                return candidate
        if candidates:
            return next(iter(candidates.values()))
        return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
