"""按配置创建并管理单个 Worker 内的全部 Action。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from smartdns.actions.fallback import FallbackAction
from smartdns.actions.filter import FilterAction
from smartdns.actions.https import HTTPSAction
from smartdns.actions.log import LogAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.actions.static import StaticAction
from smartdns.models.action import (
    FallbackActionConfig,
    FilterActionConfig,
    HTTPSActionConfig,
    LogActionConfig,
    ReplaceActionConfig,
    SpeedcheckActionConfig,
    StaticActionConfig,
)
from smartdns.utils.components import ComponentManager

if TYPE_CHECKING:
    from smartdns.actions.base import BaseAction
    from smartdns.models.action import ActionConfig
    from smartdns.nameservers.client import HTTPClient


class ActionManager(ComponentManager["ActionConfig", "BaseAction"]):
    kind = "Action"

    def __init__(self, config: list[ActionConfig], client: HTTPClient) -> None:
        super().__init__(config)
        self._client = client

    @property
    def actions(self) -> dict[str, BaseAction]:
        return self.components

    def _create(self, config: ActionConfig) -> BaseAction:
        match config:
            case LogActionConfig():
                return LogAction(config=config)
            case StaticActionConfig():
                return StaticAction(config=config)
            case ReplaceActionConfig():
                return ReplaceAction(config=config)
            case HTTPSActionConfig():
                return HTTPSAction(config=config, client=self._client)
            case FallbackActionConfig():
                return FallbackAction(config=config)
            case SpeedcheckActionConfig():
                return SpeedcheckAction(config=config)
            case FilterActionConfig():
                return FilterAction(config=config)
            case _:
                raise ValueError(f"不支持的操作类型: {config.type}")

    async def start_all(self) -> None:
        await self._start_components()
