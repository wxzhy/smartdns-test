from __future__ import annotations

from asyncio import Task, current_task, get_running_loop, shield
from collections.abc import Iterator
from collections.abc import MutableMapping as MutableMappingABC
from functools import update_wrapper
from inspect import iscoroutinefunction
from threading import Lock
from time import time
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, cast

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


def answer_expires(key: object, value: Any, now: float) -> float:
    """Answer 值缓存的 TLRUCache ttu：条目过期时刻取 Answer 自身 expiration
    （DNS TTL；负应答为 SOA TTL）。

    TTL=0 的应答 expiration 即当前时刻，而 TLRUCache 对"插入即过期"的条目
    走删除分支、对不存在的键抛 KeyError，会打穿 cached() 的写入路径；
    故钳制最小 1ms 生存期，让这类条目正常落库后立即过期。
    """
    return max(value.expiration, now + 0.001)


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
    - ``shared``：按名字注册的共享实例，各 Worker 用同一份配置构造的
      同名 Resolver 经此取到同一缓存对象。
    """

    _shared: ClassVar[dict[str, AnswerCache[Any, Any]]] = {}
    _shared_lock = Lock()

    def __init__(self, maxsize: int, ttu: TTU = answer_expires) -> None:
        self._store = TLRUCache(maxsize=maxsize, ttu=ttu, timer=time)
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
        with self._lock:
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
        with self._lock:
            return self._store.setdefault(key, default)

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

    # -- 按名共享注册表 --

    @classmethod
    def shared(cls, name: str, maxsize: int) -> AnswerCache[KT, VT]:
        """取或建按名字注册的共享缓存；同名返回同一实例。"""
        with cls._shared_lock:
            cache = cls._shared.get(name)
            if cache is None:
                cache = cls(maxsize=maxsize)
                cls._shared[name] = cache
            return cast("AnswerCache[KT, VT]", cache)

    @classmethod
    def reset_shared(cls) -> None:
        """清空共享注册表；供测试在用例间隔离同名缓存。"""
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
                return store(cache_key, await fn(*args, **kwargs))
            finally:
                task = current_task()
                with inflight_lock:
                    if task is not None and inflight.get(inflight_key) is task:
                        del inflight[inflight_key]

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
            return await shield(task)

        return update_wrapper(wrapper, fn)

    return decorator  # type: ignore[return-value]
