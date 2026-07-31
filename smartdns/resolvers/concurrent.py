from asyncio import as_completed
from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.context import Response
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.resolvers.base import BaseResolver

if TYPE_CHECKING:
    from smartdns.resolvers.manager import ResolverManager


class ConcurrentResolver(BaseResolver):
    """并发解析器"""

    def __init__(self, config: ConcurrentResolverConfig, resolvers: ResolverManager):
        super().__init__(config)
        self.resolvers: list[BaseResolver] = []
        self._upstreams: list[str] = config.resolvers
        self._manager: ResolverManager = resolvers

    async def start(self):
        """启动解析器"""
        logger.info(
            f"ConcurrentResolver {self.name} 启动成功，使用的上游解析器: {self._upstreams}"
        )
        # 查找对应的resolver
        for name in self._upstreams:
            resolver = self._manager.get(name)
            if resolver is not None:
                self.resolvers.append(resolver)
            else:
                logger.warning(f"Resolver {name} 不存在")

    async def stop(self):
        """停止解析器"""
        self.resolvers = []
        logger.info(f"ConcurrentResolver {self.name} 停止成功")

    async def query(self, request) -> Response:
        """解析域名"""
        async with create_task_group() as tg:
            coros = [
                tg.start_soon(resolver.query, request) for resolver in self.resolvers
            ]
            results: list[Response] = []
            logger.debug(
                f"ConcurrentResolver {self.name} 正在并发查询上游解析器: {self._upstreams}"
            )
            # 选取最快响应的
            for coro in as_completed(coros):
                try:
                    response = await coro
                    if not response.invalid:
                        if response.rcode == Rcode.NOERROR:
                            logger.debug(f"解析器 {self.name} 成功解析请求: {request}")
                            return response
                        # 如果响应码不是NOERROR，继续等待其他解析器的响应
                        results.append(response)
                except Exception as e:
                    logger.error(f"解析器 {self.name} 查询失败: {e}")
            if results:
                # 如果有响应码不是NOERROR的响应，返回第一个响应
                return results[0]
        # 如果没有成功的响应，返回第一个响应
        return Response.from_rcode(Rcode.SERVFAIL, upstream=self.name)
