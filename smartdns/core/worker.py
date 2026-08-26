from __future__ import annotations

from typing import TYPE_CHECKING

from aiofastnet import patch_loop
from anyio import CancelScope
from dns.rcode import Rcode
from loguru import logger

from smartdns.actions.manager import ActionManager
from smartdns.models.context import Context, Response
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.manager import ResolverManager
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from smartdns.models.config import Config
    from smartdns.models.context import Request


def _servfail() -> Response:
    """构造一个空 upstream 的 SERVFAIL 响应。"""
    return Response.from_rcode(Rcode.SERVFAIL, upstream="")


class Worker:
    def __init__(self, worker_id: int, config: Config):
        self.worker_id = worker_id
        self.config = config
        self._nameservers: NameserverManager | None = None
        self._resolvers: ResolverManager | None = None
        self._actions: ActionManager | None = None
        self._rules: list[Router] = []
        self._client: HTTPClient | None = None

    async def start(self) -> None:
        """启动 Worker 服务"""
        patch_loop()
        logger.info("Worker {} 启动", self.worker_id)
        try:
            self._client = HTTPClient(config=self.config.client)
            await self._client.start()
            self._nameservers = NameserverManager(
                config=self.config.nameservers, client=self._client
            )
            await self._nameservers.start_all()
            self._resolvers = ResolverManager(config=self.config.resolvers)
            self._actions = ActionManager(
                config=self.config.actions, client=self._client
            )
            await self._actions.start_all()
            await self._resolvers.start_all(
                nameservers=self._nameservers, actions=self._actions
            )
            self._rules = [
                Router(rule, self._resolvers, self._actions)
                for rule in self.config.routing
            ]
        except BaseException:
            with CancelScope(shield=True):
                await self.stop()
            raise

    async def stop(self) -> None:
        """停止 Worker：按依赖逆序停止各管理器并释放 HTTP 客户端。"""
        logger.info("Worker {} 停止", self.worker_id)
        components = (
            ("Resolver", self._resolvers, "stop_all"),
            ("Action", self._actions, "stop_all"),
            ("Nameserver", self._nameservers, "stop_all"),
            ("HTTP 客户端", self._client, "stop"),
        )
        for label, component, method_name in components:
            if component is None:
                continue
            try:
                await getattr(component, method_name)()
            except Exception:
                logger.exception("Worker {} 停止 {} 失败", self.worker_id, label)
        rules = getattr(self, "_rules", None)
        if rules is not None:
            rules.clear()
        self._resolvers = None
        self._nameservers = None
        self._actions = None
        self._client = None

    async def handle(self, request: Request) -> Response:
        """处理请求"""
        ctx = Context(worker_id=self.worker_id, request=request)
        await self.process(ctx)
        if ctx.response is not None:
            return ctx.response
        logger.debug("Worker {} 无法处理请求: {}", self.worker_id, request.qname)
        return _servfail()

    async def process(self, context: Context) -> None:
        """按路由表依次处理请求上下文"""
        try:
            for rule in self._rules:
                if await rule.query(context):
                    return
            context.response = _servfail()
        except Exception:
            logger.exception("Worker {} 处理请求上下文失败", self.worker_id)
            context.response = _servfail()
