"""按配置顺序创建、启动并逆序停止一组具名组件的通用管理器。"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol

from anyio import CancelScope
from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Sequence


class Component(Protocol):
    """管理器托管的组件：具名，且有异步启动/停止生命周期。"""

    name: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


class ComponentManager[ConfigT, ComponentT: Component]:
    """组件按配置顺序启动；任一启动失败时回滚已启动的组件。

    后启动的组件可能依赖先启动的组件（如 ConcurrentResolver 引用前面的
    Resolver），因此停止顺序与启动顺序相反。子类只需实现 ``_create``。
    """

    # 日志中的组件类别名称。
    kind: ClassVar[str] = "组件"

    def __init__(self, config: Sequence[ConfigT]) -> None:
        self.config = config
        self.components: dict[str, ComponentT] = {}

    def _create(self, config: ConfigT) -> ComponentT:
        raise NotImplementedError

    async def _start_components(self) -> None:
        try:
            for item in self.config:
                component = self._create(item)
                # 先登记再启动：start() 中途失败的组件也要参与回滚。
                self.components[component.name] = component
                await component.start()
        except BaseException:
            with CancelScope(shield=True):
                await self.stop_all()
            raise
        logger.debug("已启动 {} 个 {}", len(self.components), self.kind)

    def get(self, name: str) -> ComponentT | None:
        return self.components.get(name)

    async def stop_all(self) -> None:
        components = list(self.components.values())
        self.components.clear()
        for component in reversed(components):
            try:
                await component.stop()
            except Exception:
                logger.exception("停止 {} {} 失败", self.kind, component.name)
