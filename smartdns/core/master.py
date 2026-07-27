from __future__ import annotations

import random
from asyncio import wrap_future
from contextlib import ExitStack
from typing import TYPE_CHECKING

from anyio.from_thread import BlockingPortal, start_blocking_portal
from dns.rcode import Rcode
from loguru import logger

from smartdns.core.cache import TTLCache

from .worker import Worker

if TYPE_CHECKING:
    from concurrent.futures import Future

    from dns.resolver import Answer

    from smartdns.models.config import Config
    from smartdns.models.context import Request


class Master:
    def __init__(self, config: Config):
        """初始化 Master 对象"""
        self.config = config
        self.worker_count = config.worker_count
        self.workers: list[Worker] = []
        self.portals: list[BlockingPortal] = []
        self._cache = (
            TTLCache(maxsize=config.cache_size) if config.cache_size > 0 else None
        )

    async def start(self) -> None:
        """启动 Master 服务"""
        logger.info("启动 Master 服务")
        with ExitStack() as stack:
            # 批量启动子线程
            for i in range(self.worker_count):
                worker = Worker(worker_id=i, config=self.config)
                ctx = start_blocking_portal(backend_options={"use_uvloop": True})
                portal = stack.enter_context(ctx)
                self.portals.append(portal)
                self.workers.append(worker)
                future: Future = portal.start_task_soon(worker.start)
                await wrap_future(future)
                logger.info(f"创建Worker {i}")
            # 启动所有listener
            # logger.info("启动所有监听器")
            # self.listener_manager = ListenerManager(config=self.config.listeners)
            # await self.listener_manager.start_all(handler=self.dispatch)

    async def dispatch(self, request: Request) -> Answer:
        """分发请求到Worker并返回响应Message"""
        logger.info(f"Master接收到请求: {request}")
        # 读取缓存
        cached_response = self._cache.cache_get(request) if self._cache else None
        if cached_response is not None:
            logger.debug(f"从缓存中获取响应: {cached_response}")
            return cached_response
        # 随机选择一个worker处理
        worker_id = random.randint(0, self.worker_count - 1)
        portal = self.portals[worker_id]
        worker = self.workers[worker_id]
        logger.info(f"分发请求到Worker {worker_id}: {request}")
        # 使用blocking portal将请求发送到对应的worker
        future: Future = portal.start_task_soon(worker.handle, request)
        try:
            result = await wrap_future(future)
            logger.info(f"Worker {worker_id}处理完成请求: {request}, 响应: {result}")
            # 将响应缓存起来
            if self._cache:
                self._cache.cache_set(request, result)
            return result
        except Exception as e:
            logger.error(f"分发请求到Worker {worker_id}时发生错误: {e}")
            return request.make_error(Rcode.SERVFAIL)
