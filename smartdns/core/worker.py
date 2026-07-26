from __future__ import annotations

from typing import TYPE_CHECKING

from anyio import sleep
from dns.message import make_response
from dns.rcode import Rcode
from loguru import logger

if TYPE_CHECKING:
    from dns.message import Message

    from smartdns.models.config import Config
    from smartdns.models.context import Context, Request


class Worker:
    def __init__(self, worker_id: int, config: Config):
        self.worker_id = worker_id
        self.config = config

    async def start(self) -> None:
        """启动 Worker 服务"""
        logger.info(f"Worker {self.worker_id} 启动")

    async def handle(self, request: Request) -> Message:
        """处理请求"""
        logger.info(f"Worker {self.worker_id} 处理请求: {request}")
        # TODO: 实现真正的上游解析逻辑
        await sleep(0.5)
        response = make_response(request.msg, True, our_payload=1232, pad=0)
        response.set_rcode(Rcode.NOERROR)
        return response

    async def process(self, context: Context) -> None:
        """处理请求上下文"""
        logger.info(f"Worker {self.worker_id} 处理请求上下文: {context}")
