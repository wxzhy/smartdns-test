from dns.rdatatype import to_text
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import LogActionConfig
from smartdns.models.context import Context


class LogAction(BaseAction):
    """日志 Action，用于记录请求摘要"""

    def __init__(self, config: LogActionConfig):
        super().__init__(config)
        self.text = config.text

    async def start(self) -> None:
        logger.info(f"启动 Log Action {self.name}: {self.text}")

    async def on_request(self, context: Context) -> None:
        request = context.request
        logger.info(
            f"[{self.text}] {request.qname} {to_text(request.rdtype)} "
            f"from {request.remote_address}"
        )
