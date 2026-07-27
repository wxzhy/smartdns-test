from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import ActionConfig
from smartdns.models.context import Context


class LogAction(BaseAction):
    """日志 Action，用于记录请求信息"""

    def __init__(self, config: ActionConfig):
        super().__init__(config)
        self.text = config.text

    async def start(self):
        logger.info(f"LogAction {self.name} started with text: {self.text}")

    async def stop(self):
        logger.info(f"LogAction {self.name} stopped")

    async def on_request(self, context: Context):
        logger.info(f"LogAction {self.name} on_request: {context.request}")
