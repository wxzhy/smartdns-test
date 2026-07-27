from __future__ import annotations

from dns.rcode import Rcode
from loguru import logger

from smartdns.models.config import Config
from smartdns.models.context import Context, Request, Response


class Worker:
    def __init__(self, worker_id: int, config: Config):
        self.worker_id = worker_id
        self.config = config

    async def start(self) -> None:
        """启动 Worker 服务"""
        logger.info(f"Worker {self.worker_id} 启动")

    async def handle(self, request: Request) -> Response:
        """处理请求"""
        logger.info(f"Worker {self.worker_id} 处理请求: {request}")
        ctx = Context(worker_id=self.worker_id, request=request)
        await self.process(ctx)
        if ctx.response:
            return ctx.response
        return Response.from_rcode(Rcode.SERVFAIL, upstream="")

    async def process(self, context: Context) -> bool:
        """处理请求上下文"""
        logger.info(f"Worker {self.worker_id} 处理请求上下文: {context}")
        return True
