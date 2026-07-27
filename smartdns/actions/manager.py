from typing import TYPE_CHECKING

from loguru import logger

from smartdns.actions.log import LogAction
from smartdns.models.action import ActionConfig

if TYPE_CHECKING:
    from smartdns.actions.base import BaseAction


class ActionManager:
    def __init__(self, config: list[ActionConfig]):
        self.config = config
        logger.debug(self.config)
        self.actions: dict[str, BaseAction] = {}

    async def start_all(self):
        for action_config in self.config:
            match action_config.type:
                case "log":
                    logger.info(
                        f"创建Log Action: {action_config.name}，日志文本: {action_config.text}"
                    )
                    action = LogAction(config=action_config)
                case _:
                    raise ValueError(f"不支持的监听器类型: {action_config.type}")
            await action.start()
            self.actions[action.name] = action

    def get(self, name: str) -> BaseAction | None:
        return self.actions.get(name, None)

    async def stop_all(self):
        for action in self.actions.values():
            await action.stop()
