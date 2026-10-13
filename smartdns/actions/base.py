"""Action 基类：定义 before/after/resolver 各阶段的 hook。"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartdns.models.action import BaseActionConfig
    from smartdns.models.context import Context, Response


class BaseAction:
    """Base Action 类。

    生命周期方法与 hook 默认 no-op，各 Action 只覆写关心的阶段；
    放到"错误"阶段时即无操作，而非抛 NotImplementedError 被吞成 SERVFAIL。
    """

    def __init__(self, config: BaseActionConfig):
        self.name = config.name
        self.config = config

    async def start(self) -> None:
        """启动 Action"""

    async def stop(self) -> None:
        """停止 Action"""

    async def on_request(self, context: Context) -> None:
        """转发到 resolver 之前调用（before 阶段）。"""

    async def on_resolver(self, context: Context, response: Response) -> None:
        """转发到 resolver 之后调用（after 阶段）。"""

    async def on_response(self, context: Context) -> None:
        """转发到客户端之前调用（after 阶段）。"""

    async def on_subquery(self, context: Context, response: Response) -> None:
        """子查询完成后调用（on_response 阶段设置 context.subquery 后触发）。"""
