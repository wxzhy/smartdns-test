from os import cpu_count
from typing import ClassVar

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from smartdns.models.listener import ListenerConfig
from smartdns.models.nameserver import NameserverConfig


class Config(BaseSettings):
    """配置文件"""

    # 配置文件路径，可通过 set_config_file 在实例化前修改
    config_file: ClassVar[str] = "config.yaml"

    model_config = SettingsConfigDict(yaml_file="config.yaml")
    worker_count: int = Field(default=cpu_count() or 1, ge=1, description="工作线程数")
    cache_size: int = Field(default=1024, ge=1, description="缓存大小")
    listeners: list[ListenerConfig] = Field(default=[], description="监听器配置列表")
    nameservers: list[NameserverConfig] = Field(
        default=[], description="上游DNS服务器配置列表"
    )
    actions: list[ActionConfig] = Field(default=[], description="动作配置列表")

    @classmethod
    def set_config_file(cls, config_file: str) -> None:
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
