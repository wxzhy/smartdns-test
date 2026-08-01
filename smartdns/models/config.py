from os import cpu_count
from pathlib import Path
from typing import ClassVar

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from smartdns.models.action import ActionConfig
from smartdns.models.geodata import GeoDataConfig
from smartdns.models.listener import ListenerConfig
from smartdns.models.nameserver import NameserverConfig
from smartdns.models.resolver import ResolverConfig
from smartdns.models.rule import Rule


class Config(BaseSettings):
    """配置文件"""

    # 配置文件路径，可通过 set_config_file 在实例化前修改
    config_file: ClassVar[Path] = Path("config.yaml")

    model_config = SettingsConfigDict(yaml_file="config.yaml")
    worker_count: int = Field(default=cpu_count() or 1, ge=1, description="工作线程数")
    cache_size: int = Field(default=10000, ge=0, description="缓存大小")
    geodata: GeoDataConfig = Field(default=GeoDataConfig(), description="Geo数据配置")
    listeners: list[ListenerConfig] = Field(default=[], description="监听器配置列表")
    nameservers: list[NameserverConfig] = Field(
        default=[], description="上游DNS服务器配置列表"
    )
    resolvers: list[ResolverConfig] = Field(
        default=[], description="上游DNS解析器配置列表"
    )
    actions: list[ActionConfig] = Field(default=[], description="动作配置列表")
    routing: list[Rule] = Field(default=[], description="路由配置列表")

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
            YamlConfigSettingsSource(settings_cls, yaml_file=cls.config_file),
            env_settings,
        )
