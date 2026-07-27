from smartdns.models.action import BaseActionConfig
from smartdns.models.context import Context, Request, Response


class BaseAction:
    """Base Action 类。"""

    def __init__(self, config: BaseActionConfig):
        self.name = config.name
        self.config = config

    async def start(self):
        """启动 Action"""
        raise NotImplementedError

    async def stop(self):
        """停止 Action"""
        raise NotImplementedError

    async def on_request(self, context: Context):
        """在处理请求时，转发到resolver之前调用"""
        raise NotImplementedError

    async def pre_upstream(self, context: Context, request: Request):
        """在resolver转发请求之前调用"""
        raise NotImplementedError

    async def post_upstream(
        self, context: Context, request: Request, response: Response
    ):
        """在resolver转发请求，收到响应之后调用"""
        raise NotImplementedError

    async def on_subquery(self, context: Context):
        """在处理子查询时调用"""
        raise NotImplementedError

    async def on_response(self, context: Context):
        """在处理响应时，转发到客户端之前调用"""
        raise NotImplementedError
