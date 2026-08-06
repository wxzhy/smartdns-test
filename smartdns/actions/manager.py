from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from smartdns.actions.fallback import FallbackAction
from smartdns.actions.https import HTTPSAction
from smartdns.actions.log import LogAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.static import StaticAction
from smartdns.models.action import (
    FallbackActionConfig,
    HTTPSActionConfig,
    LogActionConfig,
    ReplaceActionConfig,
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
        for action_config in self.config:
            match action_config:
                case LogActionConfig():
                    logger.info(f"创建Log Action: {action_config.name}")
                    action: BaseAction = LogAction(config=action_config)
                case StaticActionConfig():
                    logger.info(f"创建Static Action: {action_config.name}")
                    action = StaticAction(config=action_config)
                case ReplaceActionConfig():
                    logger.info(f"创建Replace Action: {action_config.name}")
                    action = ReplaceAction(config=action_config)
                case HTTPSActionConfig():
                    logger.info(f"创建HTTPS Action: {action_config.name}")
                    action = HTTPSAction(config=action_config, client=self._client)
                case FallbackActionConfig():
                    logger.info(f"创建Fallback Action: {action_config.name}")
                    action = FallbackAction(config=action_config)
                case _:
                    raise ValueError(f"不支持的操作类型: {action_config.type}")
            await action.start()
            if action.name in self.actions:
                logger.warning(f"Action 名称重复，后者覆盖前者: {action.name}")
            self.actions[action.name] = action

    def get(self, name: str) -> BaseAction | None:
        return self.actions.get(name)

    async def stop_all(self) -> None:
        for action in self.actions.values():
            await action.stop()
