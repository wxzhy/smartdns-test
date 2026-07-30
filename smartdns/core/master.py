from asyncio import wrap_future
from contextlib import ExitStack
from random import randint
from typing import TYPE_CHECKING

from aiofastnet import patch_loop
from anyio.from_thread import BlockingPortal, start_blocking_portal
from dns.rcode import Rcode
from loguru import logger

from smartdns.core.cache import TTLCache
from smartdns.listeners.manager import ListenerManager
from smartdns.routing.manager import init_geo_manager

from .worker import Worker

if TYPE_CHECKING:
    from concurrent.futures import Future

    from dns.message import Message

    from smartdns.models.config import Config
    from smartdns.models.context import Request, Response


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
        self._listener_manager = None  # ListenerManager实例，稍后初始化

    async def start(self) -> None:
        """启动 Master 服务"""
        patch_loop()
        logger.info("启动 Master 服务")
        # 初始化Geo数据
        if self.config.geodata:
            init_geo_manager(self.config.geodata)
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
            logger.info("启动所有监听器")
            self.listener_manager = ListenerManager(config=self.config.listeners)
            await self.listener_manager.start_all(handler=self.dispatch)

    async def dispatch(self, request: Request) -> Message | None:
        """分发请求到Worker并返回响应Message"""
        logger.info(f"Master接收到请求: {request}")
        # 读取缓存
        if self._cache is not None:
            cached_response = self._cache.cache_get(request)
            if cached_response is not None:
                logger.debug(f"从缓存中获取响应: {cached_response}")
                return request.make_answer(cached_response)
        # 随机选择一个worker处理
        worker_id = randint(0, self.worker_count - 1)
        portal = self.portals[worker_id]
        worker = self.workers[worker_id]
        logger.info(f"分发请求到Worker {worker_id}: {request}")
        # 使用blocking portal将请求发送到对应的worker
        future: Future = portal.start_task_soon(worker.handle, request)
        try:
            result: Response = await wrap_future(future)
            logger.info(f"Worker {worker_id}处理完成请求: {request}, 响应: {result}")
            if result.rcode != Rcode.NOERROR:
                logger.warning(
                    f"Worker {worker_id}处理请求 {request} 返回错误码: {result.rcode}"
                )
                return request.make_error(Rcode.SERVFAIL)
            if result.ans is not None:
                # 将响应缓存起来
                if self._cache:
                    self._cache.cache_set(request, result.ans)
                logger.debug(f"返回响应: {result.ans.response}")
                return request.make_answer(result.ans)
            return None
        except Exception as e:
            logger.error(f"分发请求到Worker {worker_id}时发生错误: {e}")
            return request.make_error(Rcode.SERVFAIL)
