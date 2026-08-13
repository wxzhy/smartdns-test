from typing import TYPE_CHECKING

from smartdns.models.config import Config

if TYPE_CHECKING:
    from pathlib import Path


def test_config_reads_utf8_yaml(tmp_path: Path) -> None:
    """Windows 等非 UTF-8 系统区域也应能读取带中文注释的配置。"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("# 中文注释\nworker_count: 1\n", encoding="utf-8")
    original = Config.config_file
    try:
        Config.set_config_file(config_file)
        assert Config().worker_count == 1
    finally:
        Config.set_config_file(original)
