from __future__ import annotations

from typing import TYPE_CHECKING

from anyio import CancelScope
from loguru import logger

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

if TYPE_CHECKING:
    from smartdns.actions.base import BaseAction
    from smartdns.models.action import ActionConfig
    from smartdns.nameservers.client import HTTPClient


class ActionManager:
    def __init__(self, config: list[ActionConfig], client: HTTPClient):
        self.config = config
        self.actions: dict[str, BaseAction] = {}
        self._client = client

    async def start_all(self) -> None:
        try:
            for action_config in self.config:
                match action_config:
                    case LogActionConfig():
                        action: BaseAction = LogAction(config=action_config)
                    case StaticActionConfig():
                        action = StaticAction(config=action_config)
                    case ReplaceActionConfig():
                        action = ReplaceAction(config=action_config)
                    case HTTPSActionConfig():
                        action = HTTPSAction(config=action_config, client=self._client)
                    case FallbackActionConfig():
                        action = FallbackAction(config=action_config)
                    case SpeedcheckActionConfig():
                        action = SpeedcheckAction(config=action_config)
                    case FilterActionConfig():
                        action = FilterAction(config=action_config)
                    case _:
                        raise ValueError(f"不支持的操作类型: {action_config.type}")
                self.actions[action.name] = action
                await action.start()
        except BaseException:
            with CancelScope(shield=True):
                await self.stop_all()
            raise

    def get(self, name: str) -> BaseAction | None:
        return self.actions.get(name)

    async def stop_all(self) -> None:
        actions = list(self.actions.values())
        self.actions.clear()
        for action in reversed(actions):
            try:
                await action.stop()
            except Exception:
                logger.exception("停止 Action {} 失败", action.name)
