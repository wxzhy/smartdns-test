"""generic-connection-pool 0.8.1 的取消回滚兼容层。

复用依赖的容量、空闲回收与连接寿命管理，只修正获取路径遗漏
CancelledError 的回滚，并保护 AnyIO 持续取消下的锁释放和连接归还。
"""

from __future__ import annotations

from asyncio import wait_for
from contextlib import asynccontextmanager
from importlib.metadata import version
from typing import TYPE_CHECKING

from anyio import CancelScope
from generic_connection_pool import exceptions
from generic_connection_pool.asyncio import ConnectionPool
from generic_connection_pool.common import ConnectionInfo, EventType, Timer
from loguru import logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Hashable

    from generic_connection_pool.asyncio.pool import EndpointPool

# 本模块覆写了依赖的私有方法（_pools、try_acquire_or_reserve、
# attach_and_unreserve、_event_queue 等），只针对此版本核对过。
SUPPORTED_POOL_VERSION = "0.8.1"
_installed_pool_version = version("generic-connection-pool")
if _installed_pool_version != SUPPORTED_POOL_VERSION:
    logger.warning(
        "generic-connection-pool {} 未经兼容层验证（仅支持 {}），连接池可能失效",
        _installed_pool_version,
        SUPPORTED_POOL_VERSION,
    )


class CancellationSafeConnectionPool[EndpointT: Hashable, ConnectionT: Hashable](
    ConnectionPool[EndpointT, ConnectionT]
):
    @asynccontextmanager
    async def _endpoint(self, endpoint: EndpointT) -> AsyncIterator[EndpointPool]:
        manager = self._pools.acquired(endpoint, setdefault=True)
        pool = await manager.__aenter__()
        try:
            yield pool
        finally:
            with CancelScope(shield=True):
                await manager.__aexit__(None, None, None)

    async def acquire(
        self, endpoint: EndpointT, timeout: float | None = None
    ) -> ConnectionT:
        timeout = self._acquire_timeout if timeout is None else timeout
        conn = await self._acquire_connection(endpoint, timeout)
        try:
            await self._connection_manager.on_acquire(endpoint, conn)
        except BaseException:
            with CancelScope(shield=True):
                await self._release_connection(endpoint, conn)
            raise
        return conn

    async def _acquire_connection(
        self, endpoint: EndpointT, timeout: float | None
    ) -> ConnectionT:
        timer = Timer(timeout)
        while True:
            if self._stopped:
                raise exceptions.ConnectionPoolClosedError
            async with self._endpoint(endpoint) as pool:
                info, extra = await pool.try_acquire_or_reserve(timeout=timer.remains)
                if info is None:
                    try:
                        info = await self._create_connection(endpoint, timer.remains)
                        # 创建完成后，转移所有权与撤销预留须作为一个完整步骤。
                        with CancelScope(shield=True):
                            await pool.attach_and_unreserve(info, acquired=True)
                    except BaseException:
                        # _create_connection 归还全局容量，这里归还端点预留。
                        with CancelScope(shield=True):
                            await pool.unreserve()
                            # Task.cancel() 也可能打断等待池锁的所有权转移。
                            if info is not None:
                                self._decrease_pool_size()
                                await self._dispose_connection(
                                    info, self._dispose_timeout
                                )
                        raise
                else:
                    self._event_queue.remove((EventType.LIFETIME, endpoint, info.conn))
                    if extra:
                        self._event_queue.remove(
                            (EventType.IDLETIME, endpoint, info.conn)
                        )
                    try:
                        alive = await wait_for(
                            self._connection_manager.check_aliveness(
                                endpoint, info.conn
                            ),
                            timeout=timer.remains,
                        )
                    except BaseException:
                        with CancelScope(shield=True):
                            await self._release_connection(endpoint, info.conn)
                        raise
                    if not alive:
                        with CancelScope(shield=True):
                            await pool.detach(info.conn, acquired=True)
                            self._decrease_pool_size()
                            await self._dispose_connection(info, self._dispose_timeout)
                            await self._connection_manager.on_connection_dead(
                                endpoint, info.conn
                            )
                        continue
                return info.conn

    async def _create_connection(
        self, endpoint: EndpointT, timeout: float | None = None
    ) -> ConnectionInfo[EndpointT, ConnectionT]:
        timer = Timer(timeout)
        while True:
            if self._increase_pool_size():
                try:
                    conn = await wait_for(
                        self._connection_manager.create(endpoint), timeout=timer.remains
                    )
                except BaseException:
                    self._decrease_pool_size()
                    raise
                return ConnectionInfo(endpoint, conn)
            await self._try_free_slot(timeout=timer.remains)

    async def release(self, conn: ConnectionT, endpoint: EndpointT) -> None:
        with CancelScope(shield=True):
            await super().release(conn, endpoint)
