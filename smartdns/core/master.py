from asyncio import wrap_future
from contextlib import ExitStack
from random import randint
from typing import TYPE_CHECKING, cast

from aiofastnet import patch_loop
from anyio import CancelScope
from anyio.from_thread import BlockingPortal, start_blocking_portal
from cachetools import TLRUCache
from cachetools import TTLCache as CachetoolsTTLCache
from dns.rcode import Rcode
from loguru import logger

from smartdns.actions._ping import set_cache
from smartdns.core.cache import TTLCache
from smartdns.listeners.manager import ListenerManager
from smartdns.nameservers.client import set_ech_cache
from smartdns.routing.manager import init_geo_manager

from .worker import Worker

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from dns.message import Message

    from smartdns.actions._ping import SpeedtestKey
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
            TTLCache(max_size=config.cache_size) if config.cache_size > 0 else None
        )
        self.listener_manager: ListenerManager | None = None

    async def start(self) -> None:
        """启动 Master 服务"""
        patch_loop()
        logger.info("启动 Master 服务")
        if self.config.geodata:
            init_geo_manager(self.config.geodata)
        speedtest_cache: TLRUCache = TLRUCache(
            maxsize=10000, ttu=lambda key, value, now: now + 1800
        )
        set_cache(cast("MutableMapping[SpeedtestKey, float]", speedtest_cache))
        ech_cache: CachetoolsTTLCache = CachetoolsTTLCache(maxsize=100, ttl=300)
        set_ech_cache(cast("MutableMapping[str, str | None]", ech_cache))
        with ExitStack() as stack:
            try:
                for i in range(self.worker_count):
                    worker = Worker(worker_id=i, config=self.config)
                    portal = stack.enter_context(
                        start_blocking_portal(backend_options={"use_uvloop": True})
                    )
                    self.portals.append(portal)
                    self.workers.append(worker)
                    await wrap_future(portal.start_task_soon(worker.start))
                logger.info(f"已启动 {self.worker_count} 个 Worker，开始启动监听器")
                self.listener_manager = ListenerManager(config=self.config.listeners)
                await self.listener_manager.start_all(handler=self.dispatch)
            finally:
                # 停机（含取消）时屏蔽取消以完成资源清理，再退出 ExitStack 关闭 portal。
                with CancelScope(shield=True):
                    await self.stop()

    async def stop(self) -> None:
        """停止 Master：关闭监听器并停止各 worker（释放上游/HTTP 客户端等资源）。"""
        logger.info("停止 Master 服务")
        listener_manager = self.listener_manager
        self.listener_manager = None
        if listener_manager is not None:
            try:
                await listener_manager.stop_all()
            except Exception:
                logger.exception("停止监听器失败")
        worker_portals = list(zip(self.workers, self.portals, strict=False))
        self.workers.clear()
        self.portals.clear()
        for worker, portal in worker_portals:
            try:
                await wrap_future(portal.start_task_soon(worker.stop))
            except Exception:
                logger.exception(f"停止 Worker {worker.worker_id} 失败")

    async def dispatch(self, request: Request) -> Message | None:
        """分发请求到 Worker 并返回响应 Message。"""
        if self._cache is not None:
            cached = self._cache.cache_get(request)
            if cached is not None:
                logger.debug(f"缓存命中: {request.qname}")
                return request.make_answer(cached)
        worker_id = randint(0, self.worker_count - 1)
        portal = self.portals[worker_id]
        worker = self.workers[worker_id]
        try:
            result: Response = await wrap_future(
                portal.start_task_soon(worker.handle, request)
            )
            if result.rcode != Rcode.NOERROR:
                logger.warning(
                    f"Worker {worker_id} 请求 {request.qname} 返回 {result.rcode}"
                )
                return request.make_error(result.rcode)
            if result.ans is not None:
                if self._cache is not None:
                    self._cache.cache_set(request, result.ans)
                return request.make_answer(result.ans)
            return None
        except Exception:
            logger.exception(f"分发请求到 Worker {worker_id} 失败")
            return request.make_error(Rcode.SERVFAIL)
