"""按配置创建并管理单个 Worker 内的全部 Resolver。"""

from typing import TYPE_CHECKING

from smartdns.models.resolver import (
    AioDNSResolverConfig,
    ConcurrentResolverConfig,
    PlainResolverConfig,
    ResolverConfig,
)
from smartdns.resolvers.aiodns import AioDNSResolver
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.resolvers.plain import PlainResolver
from smartdns.utils.components import ComponentManager

if TYPE_CHECKING:
    from smartdns.actions.manager import ActionManager
    from smartdns.nameservers.manager import NameserverManager
    from smartdns.resolvers.base import BaseResolver


class ResolverManager(ComponentManager[ResolverConfig, "BaseResolver"]):
    kind = "Resolver"

    def __init__(self, config: list[ResolverConfig]) -> None:
        super().__init__(config)
        self._nameservers: NameserverManager | None = None
        self._actions: ActionManager | None = None

    @property
    def resolvers(self) -> dict[str, BaseResolver]:
        return self.components

    def _create(self, config: ResolverConfig) -> BaseResolver:
        match config:
            case PlainResolverConfig():
                assert self._nameservers is not None
                return PlainResolver(config=config, nameservers=self._nameservers)
            case AioDNSResolverConfig():
                return AioDNSResolver(config=config)
            case ConcurrentResolverConfig():
                assert self._actions is not None
                # 配置校验保证只引用排在前面的 Resolver，按顺序启动即可解析。
                return ConcurrentResolver(
                    config=config, resolvers=self, actions=self._actions
                )
            case _:
                raise ValueError(f"不支持的解析器类型: {config.type}")

    async def start_all(
        self, nameservers: NameserverManager, actions: ActionManager
    ) -> None:
        self._nameservers = nameservers
        self._actions = actions
        await self._start_components()
