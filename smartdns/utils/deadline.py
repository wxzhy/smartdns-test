"""把请求的跨线程截止时刻与当前任务的取消范围合并。"""

from asyncio import get_running_loop
from math import inf, isfinite
from threading import Lock
from time import monotonic
from typing import TYPE_CHECKING

from anyio import CancelScope, current_effective_deadline, current_time

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from collections.abc import Callable
    from types import TracebackType

    from smartdns.models.context import Request


def time_left(deadline: float) -> float:
    """距 monotonic 截止时刻的剩余秒数（不小于 0），供 fail_after 等期限使用。"""
    return max(0.0, deadline - monotonic())


class SharedDeadline:
    """共享查询的等待者期限；通知须在各自 Worker 循环内更新取消范围。"""

    def __init__(self) -> None:
        self._lock = Lock()
        self._waiters: dict[object, float | None] = {}
        self._watchers: dict[object, tuple[AbstractEventLoop, Callable[[], None]]] = {}

    def add(self, deadline: float | None) -> object:
        token = object()
        with self._lock:
            self._waiters[token] = deadline
            watchers = list(self._watchers.values())
        self._notify(watchers)
        return token

    def remove(self, token: object) -> bool:
        with self._lock:
            self._waiters.pop(token, None)
            watchers = list(self._watchers.values())
            empty = not self._waiters
        self._notify(watchers)
        return empty

    @staticmethod
    def _notify(
        watchers: list[tuple[AbstractEventLoop, Callable[[], None]]],
    ) -> None:
        for loop, callback in watchers:
            try:
                loop.call_soon_threadsafe(callback)
            except RuntimeError:
                # 已退出的循环不再使用此共享查询。
                continue

    def deadline(self, *, response_ready: bool) -> float | None:
        now = monotonic()
        with self._lock:
            values = [
                inf if value is None else value
                for value in self._waiters.values()
                if value is None or value > now
            ]
        if not values:
            return now
        value = min(values) if response_ready else max(values)
        return value if isfinite(value) else None

    def watch(self, callback: Callable[[], None]) -> object:
        token = object()
        with self._lock:
            self._watchers[token] = (get_running_loop(), callback)
        return token

    def unwatch(self, token: object) -> None:
        with self._lock:
            self._watchers.pop(token, None)


class ResponseScope:
    """未取得答案时使用最晚期限，已有答案后按最早等待者预算收尾。"""

    def __init__(
        self, request: Request, limit: float | None, *, response_ready: bool
    ) -> None:
        self._request = request
        self._shared = request.shared_deadline
        self._limit = limit
        self._limit_deadline = inf if limit is None else current_time() + limit
        self._ready = response_ready
        self._scope = CancelScope()
        self._watch: object | None = None
        self._active = False

    def _refresh(self) -> None:
        if not self._active or self._shared is None:
            return
        deadline = self._shared.deadline(response_ready=self._ready)
        now = current_time()
        remaining = inf if deadline is None else time_left(deadline)
        budget = (
            max(0.0, remaining - max(0.05, remaining * 0.1))
            if isfinite(remaining)
            else inf
        )
        self._scope.deadline = min(self._limit_deadline, now + budget)

    def __enter__(self) -> ResponseScope:
        if self._shared is None:
            timeout = response_timeout(self._request, self._limit)
            self._scope.deadline = inf if timeout is None else current_time() + timeout
        else:
            self._active = True
            self._watch = self._shared.watch(self._refresh)
            self._refresh()
        self._scope.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._active = False
        if self._shared is not None and self._watch is not None:
            self._shared.unwatch(self._watch)
        return self._scope.__exit__(exc_type, exc, traceback)

    def response_ready(self) -> None:
        self._ready = True
        self._refresh()


def response_scope(
    request: Request,
    limit: float | None = None,
    *,
    response_ready: bool = False,
) -> ResponseScope:
    return ResponseScope(request, limit, response_ready=response_ready)


def response_timeout(request: Request, limit: float | None = None) -> float | None:
    """保留剩余预算的 10%（至少 50ms）；无外层期限时沿用 limit。"""
    remaining = current_effective_deadline() - current_time()
    deadline = (
        request.shared_deadline.deadline(response_ready=False)
        if request.shared_deadline is not None
        else request.deadline
    )
    if deadline is not None:
        remaining = min(remaining, deadline - monotonic())
    if not isfinite(remaining) and remaining > 0:
        return limit
    budget = max(0.0, remaining - max(0.05, remaining * 0.1))
    return min(limit, budget) if limit is not None else budget
