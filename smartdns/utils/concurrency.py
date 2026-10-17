"""跨线程事件循环的协作工具：协程提交与可取消的全局容量限制（不轮询）。"""

from asyncio import get_running_loop, run_coroutine_threadsafe
from collections import deque
from threading import Lock
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop, Future
    from collections.abc import Coroutine
    from concurrent import futures


def submit_threadsafe[T](
    coroutine: Coroutine[Any, Any, T], loop: AbstractEventLoop
) -> futures.Future[T]:
    """把协程排入另一线程的事件循环；提交失败时关闭协程，避免 never awaited 警告。"""
    try:
        return run_coroutine_threadsafe(coroutine, loop)
    except BaseException:
        coroutine.close()
        raise


class _Waiter:
    def __init__(self, future: Future[None]) -> None:
        self.future = future
        self.granted = False


def _wake(waiter: _Waiter) -> None:
    if not waiter.future.done():
        waiter.future.set_result(None)


class GlobalCapacityLimiter:
    def __init__(self, value: int) -> None:
        if value < 1:
            raise ValueError("容量必须大于 0")
        self._capacity = value
        self._available = value
        self._lock = Lock()
        self._waiters: deque[_Waiter] = deque()

    async def acquire(self) -> None:
        waiter = _Waiter(get_running_loop().create_future())
        with self._lock:
            if self._available:
                self._available -= 1
                return
            self._waiters.append(waiter)
        try:
            await waiter.future
        except BaseException:
            with self._lock:
                if waiter.granted:
                    waiter.granted = False
                    self._release_locked()
                else:
                    self._waiters.remove(waiter)
            raise

    def _release_locked(self) -> None:
        while self._waiters:
            waiter = self._waiters.popleft()
            loop = waiter.future.get_loop()
            if waiter.future.cancelled() or loop.is_closed():
                # 被取消的等待者在 acquire 的异常分支移除；先标记为已
                # 领取，确保该分支仍会归还此处转移给它的名额。
                waiter.granted = True
                if not loop.is_closed():
                    return
                waiter.granted = False
                continue
            waiter.granted = True
            try:
                loop.call_soon_threadsafe(_wake, waiter)
            except RuntimeError:
                waiter.granted = False
                continue
            return
        if self._available == self._capacity:
            raise ValueError("归还了未获取的名额")
        self._available += 1

    def release(self) -> None:
        with self._lock:
            self._release_locked()

    async def __aenter__(self) -> GlobalCapacityLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.release()
