from __future__ import annotations

from asyncio import CancelledError, Task, current_task, get_running_loop, shield
from collections.abc import Iterator
from collections.abc import MutableMapping as MutableMappingABC
from functools import update_wrapper
from inspect import iscoroutinefunction
from threading import Lock
from time import time
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, cast

from anyio import CancelScope
from cachetools import TLRUCache
from cachetools.keys import hashkey
from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping
    from contextlib import AbstractContextManager

    type TTU = Callable[[object, Any, float], float]


class IdentityFunction[T](Protocol):
    def __call__(self, value: T, /) -> T: ...


def _consume_task_exception(task: Task[Any]) -> None:
    """取出无人等待的任务异常，避免事件循环产生未处理异常警告。"""
    if not task.cancelled():
        task.exception()


async def _cancel_and_wait(task: Task[Any]) -> None:
    """等待底层清理完成；重复取消等待者也不能再次打断底层任务。"""
    task.cancel()
    with CancelScope(shield=True):
        while not task.done():
            try:
                await shield(task)
            except CancelledError:
                continue
            except Exception:
                break


def answer_expires(key: object, value: Any, now: float) -> float:
    """严格使用来源应答的 expiration；TTL=0 不进入持久缓存。"""
    return value.expiration


async def _fetch_through[KT, VT](key: KT, fetch: Callable[[], Awaitable[VT]]) -> VT:
    """AnswerCache.fetch 的中转协程；键由装饰器的 key 函数截取，此处透传。"""
    return await fetch()


class AnswerCache[KT, VT](MutableMappingABC[KT, VT]):
    """跨线程共享、按 Answer 自身 TTL 过期的异步应答缓存。

    存储层为 TLRUCache（ttu=answer_expires，墙钟计时）；实现 MutableMapping
    协议以兼容 cached() 的 isinstance 检查，全部操作经内部线程锁串行化，
    可被多个 Worker 事件循环（线程）同时读写。

    - ``read``/``write``：异步直读直写。
    - ``fetch``：未命中时执行 fetch_fn 并写入；同键并发经 cached() 的
      in-flight 表合并为一次执行（按事件循环隔离，跨循环首次填充可能
      各执行一次，落库由锁内 setdefault 保证只保留一份）。
    - ``shared``：按命名空间注册的共享实例；Resolver 以完整配置生成命名空间，
      让各 Worker 复用同一对象，并隔离同名但配置不同的 Resolver。
    """

    _shared: ClassVar[dict[str, AnswerCache[Any, Any]]] = {}
    _shared_lock = Lock()

    def __init__(self, maxsize: int, ttu: TTU = answer_expires) -> None:
        self._store = TLRUCache(maxsize=maxsize, ttu=ttu, timer=time)
        self._ttu = ttu
        self._lock = Lock()
        # key 函数忽略 fetch_fn 本身，同键并发合并到首个 fetch_fn。
        self._fetch_merged = cached(self, key=lambda cache_key, fetch: cache_key)(
            _fetch_through
        )

    # -- MutableMapping 协议（cached() 亦经这些方法读写）--

    def __getitem__(self, key: KT) -> VT:
        with self._lock:
            return self._store[key]

    def __setitem__(self, key: KT, value: VT) -> None:
        with self._lock, self._store.timer as now:
            if self._ttu(key, value, now) <= now:
                self._store.pop(key, None)
            else:
                self._store[key] = value

    def __delitem__(self, key: KT) -> None:
        with self._lock:
            del self._store[key]

    def __iter__(self) -> Iterator[KT]:
        with self._lock:
            # TLRUCache 无键类型参数（键形参为 object），按容器声明收窄。
            return cast("Iterator[KT]", iter(list(self._store)))

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def setdefault(self, key: KT, default: VT) -> VT:
        # 整体在锁内完成，保证并发首写只落一份（cached() 的 store 依赖此语义）。
        with self._lock, self._store.timer as now:
            try:
                return self._store[key]
            except KeyError:
                # 插入即过期时直接返回本次结果，避免 setdefault 的回读 KeyError。
                if self._ttu(key, default, now) > now:
                    self._store[key] = default
                return default

    # -- 异步读写 API --

    async def read(self, key: KT) -> VT | None:
        """读取缓存；未命中或已过期返回 None。"""
        try:
            return self[key]
        except KeyError:
            return None

    async def write(self, key: KT, value: VT) -> None:
        """写入缓存。"""
        self[key] = value

    async def fetch(self, key: KT, fetch_fn: Callable[[], Awaitable[VT]]) -> VT:
        """读缓存；未命中时执行 fetch_fn（同键并发合并）并写入后返回。"""
        return await self._fetch_merged(key, fetch_fn)

    # -- 按命名空间共享注册表 --

    @classmethod
    def shared(cls, namespace: str, maxsize: int) -> AnswerCache[KT, VT]:
        """取或建共享缓存；同一命名空间返回同一实例。"""
        with cls._shared_lock:
            cache = cls._shared.get(namespace)
            if cache is None:
                cache = cls(maxsize=maxsize)
                cls._shared[namespace] = cache
            return cast("AnswerCache[KT, VT]", cache)

    @classmethod
    def reset_shared(cls) -> None:
        """清空共享注册表；供测试在用例间隔离缓存。"""
        with cls._shared_lock:
            cls._shared.clear()


def cached[KT, VT](
    cache: (
        MutableMapping[KT, VT] | Callable[[], MutableMapping[KT, VT] | None] | None
    ),
    key: Callable[..., KT] = hashkey,  # ty: ignore[invalid-parameter-default]
    lock: AbstractContextManager[Any] | None = None,
    info: bool = False,
) -> IdentityFunction:
    """缓存异步函数结果，并在同一事件循环内合并同键调用。

    ``cache`` 可直接传入 cachetools 缓存，也可传入无参 getter，以支持运行时
    绑定缓存。缓存只保存最终结果；进行中的 Task 按事件循环隔离，不会写入共享
    cachetools 缓存。
    """
    if info:
        raise NotImplementedError("异步缓存暂不支持 info")

    def get_cache() -> MutableMapping[KT, VT] | None:
        if cache is None:
            return None
        if isinstance(cache, MutableMappingABC):
            return cast("MutableMapping[KT, VT]", cache)
        getter = cast("Callable[[], MutableMapping[KT, VT] | None]", cache)
        return getter()

    def decorator(fn: Callable[..., Awaitable[VT]]):
        if not iscoroutinefunction(fn):
            raise TypeError(f"Expected Coroutine function, got {fn}")

        inflight: dict[tuple[object, KT], Task[VT]] = {}
        waiter_counts: dict[tuple[object, KT], int] = {}
        inflight_lock = Lock()
        missing = object()

        def get_cached(cache_key: KT) -> VT | object:
            current_cache = get_cache()
            if current_cache is None:
                return missing
            try:
                if lock is not None:
                    with lock:
                        return current_cache[cache_key]
                return current_cache[cache_key]
            except KeyError:
                return missing

        def store(cache_key: KT, value: VT) -> VT:
            current_cache = get_cache()
            if current_cache is None:
                return value
            try:
                if lock is not None:
                    with lock:
                        return current_cache.setdefault(cache_key, value)
                return current_cache.setdefault(cache_key, value)
            except ValueError:
                logger.debug("缓存值过大，跳过写入")
                return value

        async def invoke(
            inflight_key: tuple[object, KT],
            cache_key: KT,
            args: tuple[Any, ...],
            kwargs: dict[str, Any],
        ) -> VT:
            try:
                value = await fn(*args, **kwargs)
                with inflight_lock:
                    # 最后一个等待者取消后，即便底层函数吞掉取消，也不能落库。
                    if inflight.get(inflight_key) is current_task():
                        return store(cache_key, value)
                return value
            finally:
                task = current_task()
                with inflight_lock:
                    if task is not None and inflight.get(inflight_key) is task:
                        del inflight[inflight_key]
                        waiter_counts.pop(inflight_key, None)

        async def wrapper(*args, **kwargs):
            cache_key = key(*args, **kwargs)
            value = get_cached(cache_key)
            if value is not missing:
                return value

            inflight_key = (get_running_loop(), cache_key)
            with inflight_lock:
                # 首次查缓存与获取 in-flight 锁之间，其他事件循环可能已完成
                # 计算并写入结果；创建新任务前再检查一次以避免重复执行。
                value = get_cached(cache_key)
                if value is not missing:
                    return value
                task = inflight.get(inflight_key)
                if task is None:
                    task = get_running_loop().create_task(
                        invoke(inflight_key, cache_key, args, kwargs)
                    )
                    task.add_done_callback(_consume_task_exception)
                    inflight[inflight_key] = task
                    waiter_counts[inflight_key] = 0
                waiter_counts[inflight_key] += 1
            try:
                return await shield(task)
            finally:
                with inflight_lock:
                    if inflight.get(inflight_key) is not task:
                        continue_cleanup = False
                    else:
                        remaining_waiters = waiter_counts[inflight_key] - 1
                        continue_cleanup = remaining_waiters == 0
                        if continue_cleanup:
                            del inflight[inflight_key]
                            del waiter_counts[inflight_key]
                        else:
                            waiter_counts[inflight_key] = remaining_waiters
                # 共享调用仍有等待者时继续运行；最后一个等待者离开后取消底层
                # 查询，使监听器超时和服务停机能真正释放 Worker / socket 资源。
                if continue_cleanup and not task.done():
                    await _cancel_and_wait(task)

        return update_wrapper(wrapper, fn)

    return decorator  # type: ignore[return-value]
