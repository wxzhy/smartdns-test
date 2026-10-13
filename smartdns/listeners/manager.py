"""按配置启动全部监听器，并在停机时等待连接与查询任务收尾。"""

from asyncio import current_task
from typing import TYPE_CHECKING

from anyio import CancelScope, Event, create_task_group
from loguru import logger

from smartdns.listeners.tcp import TCPListener
from smartdns.listeners.udp import UDPListener

if TYPE_CHECKING:
    from asyncio import Task
    from typing import Any

    from anyio.abc import TaskGroup

    from smartdns.listeners.base import BaseListener
    from smartdns.models.listener import ListenerConfig


class ListenerManager:
    def __init__(self, config: list[ListenerConfig]):
        self.config = config
        self.listeners: list[BaseListener] = []
        self._task_group: TaskGroup | None = None
        self._owner: Task[Any] | None = None
        self._finished: Event | None = None

    async def start_all(self, handler):
        self._owner = current_task()
        finished = self._finished = Event()
        try:
            async with create_task_group() as tg:
                self._task_group = tg
                for listener_config in self.config:
                    match listener_config.type:
                        case "tcp":
                            logger.info("创建TCP监听器: {}", listener_config.name)
                            listener = TCPListener(config=listener_config)
                        case "udp":
                            logger.info("创建UDP监听器: {}", listener_config.name)
                            listener = UDPListener(config=listener_config)
                        case _:
                            raise ValueError(
                                f"不支持的监听器类型: {listener_config.type}"
                            )
                    self.listeners.append(listener)
                    tg.start_soon(listener.start, handler)
        finally:
            with CancelScope(shield=True):
                try:
                    await self._close_listeners()
                finally:
                    self._task_group = None
                    self._owner = None
                    finished.set()

    async def stop_all(self):
        group = self._task_group
        if group is not None:
            group.cancel_scope.cancel()
        with CancelScope(shield=True):
            if self._finished is not None and self._owner is not current_task():
                # 先等待连接/查询任务及套接字清理，再允许 Master 关闭 Worker。
                await self._finished.wait()
            else:
                await self._close_listeners()

    async def _close_listeners(self) -> None:
        listeners = list(self.listeners)
        self.listeners.clear()
        for listener in reversed(listeners):
            try:
                await listener.stop()
            except Exception:
                logger.exception("停止监听器 {} 失败", listener.name)
