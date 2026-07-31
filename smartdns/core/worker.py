from __future__ import annotations

from aiofastnet import patch_loop
from dns.rcode import Rcode
from loguru import logger

from smartdns.models.config import Config
from smartdns.models.context import Context, Request, Response
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.manager import ResolverManager
from smartdns.models.rule import Rule
from smartdns.routing.router import Router


class Worker:
    def __init__(self, worker_id: int, config: Config):
        self.worker_id = worker_id
        self.config = config
        self._nameservers: NameserverManager | None = None
        # ResolverManager实例，稍后初始化
        self._resolvers: ResolverManager | None = None
        # 规则列表，稍后初始化
        self._rules: list[Router] = []

    async def start(self) -> None:
        """启动 Worker 服务"""
        patch_loop()
        logger.info(f"Worker {self.worker_id} 启动")
        self._nameservers = NameserverManager(config=self.config.nameservers)
        await self._nameservers.start_all()
        self._resolvers = ResolverManager(config=self.config.resolvers)
        await self._resolvers.start_all(nameservers=self._nameservers)
        for rule in self.config.routing:
            logger.debug(f"Worker {self.worker_id} 添加路由: {rule}")
            self._rules.append(Router(rule, self._resolvers))

    async def handle(self, request: Request) -> Response:
        """处理请求"""
        logger.debug(f"Worker {self.worker_id} 处理请求: {request}")
        ctx = Context(worker_id=self.worker_id, request=request)
        await self.process(ctx)
        if ctx.response:
            logger.debug(
                f"Worker {self.worker_id} 处理请求完成: {request}, 响应: {ctx.response}"
            )
            return ctx.response
        logger.debug(f"Worker {self.worker_id} 无法处理请求: {request}")
        return Response.from_rcode(Rcode.SERVFAIL, upstream="")

    async def process(self, context: Context):
        """处理请求上下文"""
        logger.info(f"Worker {self.worker_id} 处理请求上下文: {context}")
        for rule in self._rules:
            if await rule.query(context):
                logger.info(
                    f"Worker {self.worker_id} 请求 {context.request} 匹配路由 {rule.config.name}"
                )
                return
        context.response = Response.from_rcode(Rcode.SERVFAIL, upstream="")
