from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import PingConfig, SpeedcheckConfig
from smartdns.models.context import Context, Response


class SpeedcheckAction(BaseAction):
    def __init__(self, config: SpeedcheckConfig):
        super().__init__(config)
        self._speedtest = config.ping_config
        self._matcher = config.match_ip

    async def start(self) -> None:
        logger.info(f"启动 Speedcheck Action {self.name}，ping 配置: {self._speedtest}")

    async def on_resolver(self, context: Context, response: Response) -> None:
        pass

    async def on_response(self, context: Context) -> None:
        """转发到客户端之前调用（after 阶段）。"""
        pass
