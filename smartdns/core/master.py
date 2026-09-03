from __future__ import annotations

from asyncio import wrap_future
from contextlib import ExitStack
from random import randint
from time import time
from typing import TYPE_CHECKING, cast

from aiofastnet import patch_loop
from anyio import CancelScope
from anyio.from_thread import BlockingPortal, start_blocking_portal
from cachetools import TLRUCache
from cachetools import TTLCache as CachetoolsTTLCache
from dns.rcode import Rcode
from loguru import logger

from smartdns.actions._helper import clone_answer
from smartdns.actions._ping import set_cache
from smartdns.listeners.manager import ListenerManager
from smartdns.models.context import Request, Response
from smartdns.nameservers.client import set_ech_cache
from smartdns.routing.manager import init_geo_manager
from smartdns.utils.cache_async import answer_expires, cached

from .worker import Worker

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from dns.message import Message
    from dns.name import Name
    from dns.rdataclass import RdataClass
    from dns.rdatatype import RdataType
    from dns.resolver import Answer

    from smartdns.actions._ping import SpeedtestKey
    from smartdns.models.config import Config

type CacheKey = tuple[Name, RdataType, RdataClass, str, str | None]


def _cache_key(request: Request) -> CacheKey:
    # 客户端地址不入键：上游不转发客户端 ECS（plain 用固定配置 ECS，aiodns
    # 忽略），同一查询对任意客户端结果一致，按客户端分键只会摊薄命中率。
    return (
        request.qname,
        request.rdtype,
        request.rdclass,
        request.listener,
        str(request.ecs) if request.ecs is not None else None,
    )


class _UncacheableResponseError(Exception):
    """不可缓存的查询结果（无 ans 或瞬态失败 rcode），经异常通道回传 dispatch。

    cached() 只存储正常返回值；不可缓存结果借异常绕过持久缓存，
    经 in-flight 合并的等待者各自捕获并降级，语义与异常上抛不同。
    """

    def __init__(self, response: Response) -> None:
        super().__init__("uncacheable response")
        self.response = response


class Master:
    def __init__(self, config: Config):
        """初始化 Master 对象"""
        self.config = config
        self.worker_count = config.worker_count
        self.workers: list[Worker] = []
        self.portals: list[BlockingPortal] = []
        # 应答缓存：持久层为 ttu=Answer.expiration 的 TLRUCache（cache_size=0
        # 关闭），读取、写入与同键 in-flight 合并由 cached() 统一处理；dispatch
        # 仅运行于 Master 主循环，合并范围覆盖全部监听器的同键并发请求。
        self._cache = (
            TLRUCache(maxsize=config.cache_size, ttu=answer_expires, timer=time)
            if config.cache_size > 0
            else None
        )
        if self._cache is not None:
            cache = cast("MutableMapping[CacheKey, Answer]", self._cache)
            self._query_cached = cached(cache, key=_cache_key)(self._query_answer)
        else:
            self._query_cached = self._query_answer
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
        if self._cache is None:
            return self._to_client_message(request, await self._query_worker(request))
        try:
            answer = await self._query_cached(request)
        except _UncacheableResponseError as error:
            return self._to_client_message(request, error.response)
        # 复制回放：命中与未命中统一按剩余生存期刷新各 section TTL，
        # 缓存内原始 Answer 不外泄给调用方。
        remaining = max(0, int(answer.expiration - time()))
        return request.make_answer(clone_answer(answer, remaining_ttl=remaining))

    @staticmethod
    def _to_client_message(request: Request, response: Response) -> Message | None:
        """按最终 Response 构造回给监听器的 Message；无应答内容时返回 None。"""
        if response.ans is not None:
            return request.make_answer(response.ans)
        if response.rcode != Rcode.NOERROR:
            return request.make_error(response.rcode)
        return None

    async def _query_worker(self, request: Request) -> Response:
        """把请求交给随机 Worker。

        异常统一转为 SERVFAIL 响应，避免经 in-flight 合并传播给等待者。
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
            return result
        except Exception:
            logger.exception("分发请求到 Worker {} 失败", worker_id)
            return Response.from_rcode(Rcode.SERVFAIL, upstream="")

    async def _query_answer(self, request: Request) -> Answer:
        """缓存入口：可缓存结果正常返回（由 cached() 落库），其余经异常通道回传。

        负应答携带 ans（含 authority 区 SOA）时按 RFC 2308 以 Answer.expiration
        （SOA minimum）为负缓存 TTL；SERVFAIL/REFUSED 等瞬态失败即使带 ans
        也不缓存。
        """
        response = await self._query_worker(request)
        if response.ans is None or response.rcode not in (
            Rcode.NOERROR,
            Rcode.NXDOMAIN,
        ):
            raise _UncacheableResponseError(response)
        return response.ans
