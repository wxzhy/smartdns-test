from asyncio import Future, Task, get_running_loop, shield
from collections.abc import Awaitable, Callable, MutableMapping
from contextlib import AbstractContextManager
from functools import update_wrapper
from inspect import iscoroutinefunction
from typing import Any, Protocol, TypeVar

from cachetools.keys import hashkey
from loguru import logger

_KT = TypeVar("_KT")
_T = TypeVar("_T")


class IdentityFunction(Protocol):
    def __call__(self, x: _T, /) -> _T: ...


def apply_task_result_to_future(task: Task[Any], future: Future[Any]) -> None:
    if task.cancelled():
        future.cancel()
        return
    exception = task.exception()
    if exception is not None:
        future.set_exception(exception)
        return
    future.set_result(task.result())


def cached(
    cache: MutableMapping[_KT, Future[Any]] | None,
    key: Callable[..., _KT] = hashkey,
    lock: AbstractContextManager[Any] | None = None,
    info: bool = False,
) -> IdentityFunction:
    """将协程函数的结果缓存到 cache（in-flight 去重：并发同键复用同一 Future）。"""
    if info:
        raise NotImplementedError("cachetools_async does not support `info`")

    def decorator(fn: Callable[..., Awaitable]):
        if not iscoroutinefunction(fn):
            raise TypeError(f"Expected Coroutine function, got {fn}")

        async def wrapper(*args, **kwargs):
            if cache is None:
                # 无缓存：直接执行。
                return await fn(*args, **kwargs)

            k = key(*args, **kwargs)
            try:
                if lock is not None:
                    with lock:
                        future = cache[k]
                else:
                    future = cache[k]
            except KeyError:
                future = None

            if future is not None:
                if not future.done():
                    return await shield(future)
                if future.exception() is None:
                    return future.result()

            loop = get_running_loop()
            task = loop.create_task(fn(*args, **kwargs))
            f = loop.create_future()
            task.add_done_callback(lambda t: apply_task_result_to_future(t, f))
            try:
                if lock is not None:
                    with lock:
                        cache[k] = f
                else:
                    cache[k] = f
            except ValueError:
                logger.debug("缓存写入失败（值过大），跳过缓存: {}", k)
            return await shield(f)

        return update_wrapper(wrapper, fn)

    return decorator  # type: ignore[return-value]
