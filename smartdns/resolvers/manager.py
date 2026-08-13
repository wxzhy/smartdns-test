from typing import TYPE_CHECKING

from anyio import CancelScope
from loguru import logger

from smartdns.models.resolver import (
    AioDNSResolverConfig,
    ConcurrentResolverConfig,
    PlainResolverConfig,
    ResolverConfig,
)
from smartdns.resolvers.aiodns import AioDNSResolver
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.resolvers.plain import PlainResolver

if TYPE_CHECKING:
    from smartdns.actions.manager import ActionManager
    from smartdns.nameservers.manager import NameserverManager
    from smartdns.resolvers.base import BaseResolver


class ResolverManager:
    def __init__(self, config: list[ResolverConfig]) -> None:
        self.config = config
        self.resolvers: dict[str, BaseResolver] = {}

    async def start_all(
        self, nameservers: NameserverManager, actions: ActionManager
    ) -> None:
        try:
            for config in self.config:
                match config:
                    case PlainResolverConfig():
                        resolver: BaseResolver = PlainResolver(
                            config=config, nameservers=nameservers
                        )
                    case AioDNSResolverConfig():
                        resolver = AioDNSResolver(config=config)
                    case ConcurrentResolverConfig():
                        resolver = ConcurrentResolver(
                            config=config,
                            resolvers=self,
                            actions=actions,
                        )
                    case _:
                        raise ValueError(f"不支持的解析器类型: {config.type}")
                self.resolvers[resolver.name] = resolver
                await resolver.start()
        except BaseException:
            with CancelScope(shield=True):
                await self.stop_all()
            raise

    def get(self, name: str) -> BaseResolver | None:
        return self.resolvers.get(name)

    async def stop_all(self) -> None:
        resolvers = list(self.resolvers.values())
        self.resolvers.clear()
        for resolver in reversed(resolvers):
            try:
                await resolver.stop()
            except Exception:
                logger.exception("停止 Resolver {} 失败", resolver.name)
