"""跨循环通知、排队取消及授予名额后的取消竞态。"""

import asyncio
from threading import Event as ThreadEvent

import pytest
from anyio import create_task_group, fail_after
from anyio.from_thread import start_blocking_portal
from anyio.lowlevel import checkpoint

from smartdns.utils.concurrency import GlobalCapacityLimiter, submit_threadsafe


async def test_cancel_after_grant_does_not_lose_capacity() -> None:
    limiter = GlobalCapacityLimiter(1)
    await limiter.acquire()
    task = asyncio.create_task(limiter.acquire())
    await checkpoint()
    limiter.release()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with fail_after(0.5):
        async with limiter:
            pass


async def test_cancelled_waiter_is_removed_under_anyio_scope() -> None:
    limiter = GlobalCapacityLimiter(1)
    await limiter.acquire()
    async with create_task_group() as tg:
        tg.start_soon(limiter.acquire)
        await checkpoint()
        tg.cancel_scope.cancel()
    limiter.release()
    with fail_after(0.5):
        async with limiter:
            pass


async def test_release_wakes_waiter_in_other_event_loop() -> None:
    limiter = GlobalCapacityLimiter(1)
    entered = ThreadEvent()
    await limiter.acquire()

    async def use_slot() -> None:
        entered.set()
        async with limiter:
            pass

    with start_blocking_portal() as portal:
        future = portal.start_task_soon(use_slot)
        assert await asyncio.to_thread(entered.wait, 1)
        assert not future.done()
        limiter.release()
        with fail_after(1):
            await asyncio.wrap_future(future)
        with fail_after(0.5):
            async with limiter:
                pass


async def test_cross_thread_cancel_and_release_return_one_slot() -> None:
    limiter = GlobalCapacityLimiter(1)
    entered, cleaned = ThreadEvent(), ThreadEvent()
    await limiter.acquire()

    async def wait() -> None:
        entered.set()
        try:
            async with limiter:
                await asyncio.Event().wait()
        finally:
            cleaned.set()

    with start_blocking_portal() as portal:
        future = portal.start_task_soon(wait)
        assert await asyncio.to_thread(entered.wait, 1)
        future.cancel()
        limiter.release()
        assert await asyncio.to_thread(cleaned.wait, 1)
        with fail_after(0.5):
            async with limiter:
                pass


def test_submit_threadsafe_closes_coroutine_when_loop_is_closed() -> None:
    loop = asyncio.new_event_loop()
    loop.close()
    started = False

    async def job() -> None:
        nonlocal started
        started = True

    coroutine = job()
    with pytest.raises(RuntimeError):
        submit_threadsafe(coroutine, loop)
    # 已关闭的协程无法再启动，也不会触发 "never awaited" 警告。
    assert coroutine.cr_frame is None
    assert not started
