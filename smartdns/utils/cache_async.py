from __future__ import annotations

from asyncio import Task, current_task, get_running_loop, shield
from collections.abc import MutableMapping as MutableMappingABC
from functools import update_wrapper
from inspect import iscoroutinefunction
from threading import Lock
from typing import TYPE_CHECKING, Any, Protocol, cast

from cachetools.keys import hashkey
from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping
    from contextlib import AbstractContextManager


class IdentityFunction[T](Protocol):
    def __call__(self, value: T, /) -> T: ...


def _consume_task_exception(task: Task[Any]) -> None:
    """取出无人等待的任务异常，避免事件循环产生未处理异常警告。"""
    if not task.cancelled():
        task.exception()


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
