from __future__ import annotations

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
from smartdns.models.context import Request, Response
from smartdns.nameservers.client import set_ech_cache
from smartdns.routing.manager import init_geo_manager
from smartdns.utils.cache_async import cached

from .worker import Worker

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from dns.message import Message

    from smartdns.actions._ping import SpeedtestKey
    from smartdns.models.config import Config


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
                logger.info("已启动 {} 个 Worker，开始启动监听器", self.worker_count)
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
                logger.exception("停止 Worker {} 失败", worker.worker_id)

    async def dispatch(self, request: Request) -> Message | None:
        """分发请求到 Worker 并返回响应 Message。"""
        if self._cache is not None:
            cached = self._cache.cache_get(request)
            if cached is not None:
                logger.debug("缓存命中: {}", request.qname)
                return request.make_answer(cached)
        if self._cache is None:
            response = await self._query_worker(request)
        else:
            # 同键 in-flight 合并：cached 按主事件循环隔离进行中的 Task；
            # 各请求以自己的报文 ID 重建应答（DNS 应答 ID 必须匹配请求）。
            response = await _query_singleflight(
                self, self._cache._key(request), request
            )
        if response.ans is not None:
            return request.make_answer(response.ans)
        if response.rcode != Rcode.NOERROR:
            return request.make_error(response.rcode)
        return None

    async def _query_worker(self, request: Request) -> Response:
        """把请求交给随机 Worker；可缓存的结果写入缓存。

        异常统一转为 SERVFAIL 响应，避免经 singleflight 传播给等待者。
        """
        worker_id = -1
        try:
            worker_id = randint(0, self.worker_count - 1)
            # 索引在 try 内访问：停机竞态窗口（workers/portals 已清空）统一走
            # SERVFAIL 分支，而不是向监听器抛 IndexError。
            worker = self.workers[worker_id]
            portal = self.portals[worker_id]
            result: Response = await wrap_future(
                portal.start_task_soon(worker.handle, request)
            )
            if result.rcode in (Rcode.SERVFAIL, Rcode.REFUSED):
                logger.warning(
                    "Worker {} 请求 {} 返回 {}", worker_id, request.qname, result.rcode
                )
            elif result.rcode != Rcode.NOERROR:
                # NXDOMAIN 等权威否定应答属正常路径，降为 debug 避免日志噪音。
                logger.debug(
                    "Worker {} 请求 {} 返回 {}", worker_id, request.qname, result.rcode
                )
            if result.ans is not None:
                # 负应答携带 ans（含 authority 区 SOA）时原样透传，供客户端负缓存；
                # RFC 2308：NXDOMAIN 以 Answer.expiration（SOA minimum）为负缓存
                # TTL。SERVFAIL/REFUSED 等瞬态失败即使带 ans 也不缓存。
                cacheable = result.rcode in (Rcode.NOERROR, Rcode.NXDOMAIN)
                if cacheable and self._cache is not None:
                    self._cache.cache_set(request, result.ans)
            return result
        except Exception:
            logger.exception("分发请求到 Worker {} 失败", worker_id)
            return Response.from_rcode(Rcode.SERVFAIL, upstream="")


@cached(None, key=lambda master, key, request: (master, key))
async def _query_singleflight(master: Master, key: tuple, request: Request) -> Response:
    """按事件循环合并 Master 的同键查询；持久缓存仍由 TTLCache 管理。"""
    return await master._query_worker(request)
