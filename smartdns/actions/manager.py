from typing import TYPE_CHECKING

from loguru import logger

from smartdns.actions.https import HTTPSAction
from smartdns.actions.log import LogAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.static import StaticAction
from smartdns.models.action import ActionConfig
from smartdns.nameservers.client import HTTPClient

if TYPE_CHECKING:
    from smartdns.actions.base import BaseAction


class ActionManager:
    def __init__(self, config: list[ActionConfig], client: HTTPClient):
        self.config = config
        logger.debug(self.config)
        self.actions: dict[str, BaseAction] = {}
        self._client = client

    async def start_all(self):
        for action_config in self.config:
            match action_config.type:
                case "log":
                    logger.info(
                        f"创建Log Action: {action_config.name}，日志文本: {action_config.text}"
                    )
                    action = LogAction(config=action_config)
                case "static":
                    logger.info(
                        f"创建Static Action: {action_config.name}，静态响应数据: {action_config}"
                    )

                    action = StaticAction(config=action_config)
                case "replace":
                    logger.info(
                        f"创建Replace Action: {action_config.name}，替换映射: {action_config.replace_map}"
                    )

                    action = ReplaceAction(config=action_config)
                case "https":
                    logger.info(
                        f"创建HTTPS Action: {action_config.name}，添加ECH: {action_config.add_ech}，移除H3: {action_config.remove_h3}，移除Hint: {action_config.remove_hint}"
                    )
                    action = HTTPSAction(config=action_config, client=self._client)
                case _:
                    raise ValueError(f"不支持的操作类型: {action_config.type}")
            await action.start()
            self.actions[action.name] = action

    def get(self, name: str) -> BaseAction | None:
        return self.actions.get(name, None)

    async def stop_all(self):
        for action in self.actions.values():
            await action.stop()
