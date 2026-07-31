from typing import TYPE_CHECKING

from loguru import logger

from smartdns.models.resolver import ResolverConfig
from smartdns.resolvers.aiodns import AioDNSResolver
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.resolvers.plain import PlainResolver

if TYPE_CHECKING:
    from smartdns.nameservers.manager import NameserverManager
    from smartdns.resolvers.base import BaseResolver


class ResolverManager:
    def __init__(self, config: list[ResolverConfig]):
        self.config = config
        logger.debug(self.config)
        self.resolvers: dict[str, BaseResolver] = {}

    async def start_all(self, nameservers: NameserverManager):
        for resolver_config in self.config:
            match resolver_config.type:
                case "plain":
                    logger.info(f"创建Plain解析器: {resolver_config.name}")
                    resolver = PlainResolver(
                        config=resolver_config, nameservers=nameservers
                    )
                case "aiodns":
                    logger.info(
                        f"创建AioDNS解析器: {resolver_config.name}，地址: {resolver_config.nameservers}:{resolver_config.port}"
                    )
                    resolver = AioDNSResolver(config=resolver_config)
                case "concurrent":
                    logger.info(
                        f"创建Concurrent解析器: {resolver_config.name}，上游解析器: {resolver_config.resolvers}"
                    )
                    resolver = ConcurrentResolver(
                        config=resolver_config, resolvers=self
                    )
                case _:
                    raise ValueError(f"不支持的解析器类型: {resolver_config.type}")
            await resolver.start()
            self.resolvers[resolver.name] = resolver

    def get(self, name: str) -> BaseResolver | None:
        return self.resolvers.get(name, None)

    async def stop_all(self):
        for resolver in self.resolvers.values():
            await resolver.stop()
