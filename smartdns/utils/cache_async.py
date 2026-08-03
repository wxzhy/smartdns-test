from asyncio import Future, Task, get_event_loop, shield
from collections.abc import Awaitable, Callable, MutableMapping
from functools import update_wrapper
from inspect import iscoroutinefunction
from typing import (
    Any,
    ContextManager,
    Protocol,
    TypeVar,
)

from cachetools.keys import hashkey, methodkey

_KT = TypeVar("_KT")
_T = TypeVar("_T")


class IdentityFunction(Protocol):
    def __call__(self, x: _T, /) -> _T: ...


def apply_task_result_to_future(task: Task, future: Future):
    if task.cancelled():
        future.cancel()
        return

    exception = task.exception()
    if exception is not None:
        future.set_exception(exception)
        return

    future.set_result(task.result())


def cached(
    cache: MutableMapping[_KT, Future] | None,
    key: Callable[..., _KT] = hashkey,
    lock: ContextManager[Any] | None = None,
    info: bool = False,
) -> IdentityFunction:
    """Wrap a function to save results in a cache."""
    if info:
        raise NotImplementedError("cachetools_async does not support `info`")

    # if lock is not None:
    #     raise NotImplementedError("cachetools_async does not support `lock`")

    def decorator(fn: Callable[..., Awaitable]):
        if not iscoroutinefunction(fn):
            raise TypeError(f"Expected Coroutine function, got {fn}")

        async def wrapper(*args, **kwargs):
            if cache is None:
                # No cache available - run the method as normal
                return await fn(*args, **kwargs)

            k = key(*args, **kwargs)

            try:
                if lock is not None:
                    with lock:
                        future = cache[k]
                else:
                    future = cache[k]
            except KeyError:
                # key not found
                future = None

            if future is not None:
                if not future.done():
                    return await shield(future)

                if future.exception() is None:
                    return future.result()

            coro = fn(*args, **kwargs)

            loop = get_event_loop()

            # Crete a task that tracks the coroutine execution
            task = loop.create_task(coro)

            # Create a future and then tie the future and task together
            f = loop.create_future()
            task.add_done_callback(lambda t: apply_task_result_to_future(t, f))

            try:
                if lock is not None:
                    with lock:
                        cache[k] = f
                else:
                    cache[k] = f
            except ValueError:
                # value too large
                pass
            return await shield(f)

        def cache_clear():
            if cache is not None:
                cache.clear()

        wrapper.cache = cache
        wrapper.cache_key = key
        wrapper.cache_lock = None
        wrapper.cache_clear = cache_clear
        wrapper.cache_info = None

        return update_wrapper(wrapper, fn)

    return decorator  # type: ignore


def cachedmethod(
    cache: Callable[[Any], MutableMapping[_KT, Future] | None],
    key: Callable[..., _KT] = methodkey,
    lock: Callable[[Any], ContextManager[Any]] | None = None,
) -> IdentityFunction:
    """Wrap a class or instance method to save results in a cache."""
    if lock is not None:
        raise NotImplementedError("cachetools_async does not support `lock`")

    def decorator(method: Callable[..., Awaitable]):
        if not iscoroutinefunction(method):
            raise TypeError(f"Expected Coroutine function, got {method}")

        async def wrapper(self, *args, **kwargs):
            c = cache(self)
            if c is None:
                # No cache available - run the method as normal
                return await method(self, *args, **kwargs)

            k = key(self, *args, **kwargs)

            try:
                if lock is not None:
                    with lock:
                        future = c[k]
                else:
                    future = c[k]
            except KeyError:
                # key not found
                future = None

            if future is not None:
                if not future.done():
                    return await shield(future)

                if future.exception() is None:
                    return future.result()

            coro = method(self, *args, **kwargs)

            loop = get_event_loop()

            # Crete a task that tracks the coroutine execution
            task = loop.create_task(coro)

            # Create a future and then tie the future and task together
            future = loop.create_future()
            task.add_done_callback(lambda t: apply_task_result_to_future(t, future))

            try:
                if lock is not None:
                    with lock:
                        c[k] = future
                else:
                    c[k] = future
            except ValueError:
                # value too large
                pass
            return await shield(future)

        def cache_clear(self):
            c = cache(self)
            if c is not None:
                c.clear()

        wrapper.cache = cache
        wrapper.cache_key = key
        wrapper.cache_lock = None
        wrapper.cache_clear = cache_clear

        return update_wrapper(wrapper, method)

    return decorator  # type: ignore
