"""顶层配置模型：从 YAML 加载并在启动前校验组件引用与 Action 阶段。"""

from collections import Counter
from os import cpu_count
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from smartdns.models.action import ActionConfig, ActionPhase, HTTPSActionConfig
from smartdns.models.geodata import GeoDataConfig
from smartdns.models.http import HTTPClientConfig
from smartdns.models.listener import HTTPListenerConfig, ListenerConfig
from smartdns.models.nameserver import CurlNameserverConfig, NameserverConfig
from smartdns.models.resolver import (
    ConcurrentResolverConfig,
    PlainResolverConfig,
    ResolverConfig,
)
from smartdns.models.rule import Rule


class Config(BaseSettings):
    """配置文件"""

    # 配置文件路径，可通过 set_config_file 在实例化前修改
    config_file: ClassVar[Path] = Path("config.yaml")

    model_config = SettingsConfigDict(
        yaml_file="config.yaml", yaml_file_encoding="utf-8", extra="forbid"
    )
    worker_count: int = Field(default=cpu_count() or 1, ge=1, description="工作线程数")
    cache_size: int = Field(default=10000, ge=0, description="缓存大小")
    log_level: Literal[
        "TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"
    ] = Field(default="INFO", description="日志等级；DEBUG/TRACE 可用于诊断详细上下文")
    geodata: GeoDataConfig = Field(
        default_factory=GeoDataConfig, description="Geo数据配置"
    )
    client: HTTPClientConfig = Field(
        default_factory=HTTPClientConfig, description="HTTP客户端配置"
    )
    listeners: list[ListenerConfig] = Field(
        default_factory=list, description="监听器配置列表"
    )
    nameservers: list[NameserverConfig] = Field(
        default_factory=list, description="上游DNS服务器配置列表"
    )
    resolvers: list[ResolverConfig] = Field(
        default_factory=list, description="上游DNS解析器配置列表"
    )
    actions: list[ActionConfig] = Field(
        default_factory=list, description="动作配置列表"
    )
    routing: list[Rule] = Field(default_factory=list, description="路由配置列表")

    @model_validator(mode="after")
    def validate_references(self) -> Config:
        """在启动前验证名称唯一性和跨组件引用。"""
        self._ensure_unique("listener", [item.name for item in self.listeners])
        self._ensure_unique("nameserver", [item.name for item in self.nameservers])
        self._ensure_unique("resolver", [item.name for item in self.resolvers])
        self._ensure_unique("action", [item.name for item in self.actions])
        self._ensure_unique("routing rule", [item.name for item in self.routing])

        unsupported = [
            item.name for item in self.listeners if isinstance(item, HTTPListenerConfig)
        ]
        if unsupported:
            raise ValueError(
                "尚未实现 HTTP Listener，不能配置: " + ", ".join(unsupported)
            )

        nameservers = {item.name for item in self.nameservers}
        actions = {item.name for item in self.actions}
        phases = {item.name: item.phases for item in self.actions}
        resolved: set[str] = set()
        for resolver in self.resolvers:
            if isinstance(resolver, PlainResolverConfig):
                missing = set(resolver.nameservers) - nameservers
                self._raise_missing(f"resolver {resolver.name} nameservers", missing)
            elif isinstance(resolver, ConcurrentResolverConfig):
                missing = set(resolver.resolvers) - resolved
                self._raise_missing(
                    f"concurrent resolver {resolver.name} previous resolvers", missing
                )
                self._raise_missing(
                    f"concurrent resolver {resolver.name} actions",
                    set(resolver.actions) - actions,
                )
                self._ensure_phase(
                    f"concurrent resolver {resolver.name} actions",
                    resolver.actions,
                    "resolver",
                    phases,
                )
            resolved.add(resolver.name)

        for rule in self.routing:
            if rule.resolver is not None:
                self._raise_missing(
                    f"routing rule {rule.name} resolver", {rule.resolver} - resolved
                )
            self._raise_missing(
                f"routing rule {rule.name} before actions",
                set(rule.before or []) - actions,
            )
            self._raise_missing(
                f"routing rule {rule.name} after actions",
                set(rule.after or []) - actions,
            )
            self._ensure_phase(
                f"routing rule {rule.name} before actions",
                rule.before or [],
                "before",
                phases,
            )
            self._ensure_phase(
                f"routing rule {rule.name} after actions",
                rule.after or [],
                "after",
                phases,
            )

        client_resolver = self.client.resolver is not None
        ech_users = [
            item.name
            for item in self.nameservers
            if isinstance(item, CurlNameserverConfig) and isinstance(item.ech, str)
        ] + [
            item.name
            for item in self.actions
            if isinstance(item, HTTPSActionConfig) and item.add_ech
        ]
        if ech_users and not client_resolver:
            raise ValueError(
                "获取 ECH 配置需要 client.resolver，以下组件依赖它: "
                + ", ".join(ech_users)
            )
        return self

    @staticmethod
    def _ensure_unique(kind: str, names: list[str]) -> None:
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        if duplicates:
            raise ValueError(f"{kind} 名称重复: {', '.join(duplicates)}")

    @staticmethod
    def _ensure_phase(
        kind: str,
        names: list[str],
        phase: ActionPhase,
        phases: dict[str, frozenset[ActionPhase]],
    ) -> None:
        """Action 放在未实现对应 hook 的阶段时会静默失效，加载时拒绝。"""
        invalid = [
            f"{name}（支持: {', '.join(sorted(phases[name])) or '无'}）"
            for name in names
            if name in phases and phase not in phases[name]
        ]
        if invalid:
            raise ValueError(f"{kind} 放在 {phase} 阶段不会生效: {', '.join(invalid)}")

    @staticmethod
    def _raise_missing(kind: str, names: set[str]) -> None:
        if names:
            raise ValueError(f"{kind} 引用不存在或顺序无效: {', '.join(sorted(names))}")

    @classmethod
    def set_config_file(cls, config_file: Path) -> None:
        """设置配置文件路径"""
        cls.config_file = config_file

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            YamlConfigSettingsSource(
                settings_cls,
                yaml_file=cls.config_file,
                yaml_file_encoding="utf-8",
            ),
            env_settings,
        )
