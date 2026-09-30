"""Speedcheck 标签/ASN 倍率的默认配置与输入校验。"""

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from smartdns.models.action import SpeedcheckActionConfig
from smartdns.models.config import Config

if TYPE_CHECKING:
    from pathlib import Path


def test_multiplier_maps_default_to_empty() -> None:
    config = SpeedcheckActionConfig(name="speed", type="speedcheck")
    other = SpeedcheckActionConfig(name="other", type="speedcheck")

    assert config.tag_multipliers == {}
    assert config.asn_multipliers == {}
    config.tag_multipliers["cn"] = 0.5
    config.asn_multipliers[64500] = 2.0
    assert other.tag_multipliers == {}
    assert other.asn_multipliers == {}


@pytest.mark.parametrize("field", ["tag_multipliers", "asn_multipliers"])
@pytest.mark.parametrize(
    "multiplier", [0.0, -1.0, float("inf"), float("-inf"), float("nan")]
)
def test_invalid_multiplier_is_rejected(field: str, multiplier: float) -> None:
    key = "cn" if field == "tag_multipliers" else 64500
    with pytest.raises(ValidationError, match=field):
        SpeedcheckActionConfig.model_validate(
            {"name": "speed", "type": "speedcheck", field: {key: multiplier}}
        )


def test_multiplier_maps_load_from_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "actions:\n"
        "  - name: speed\n"
        "    type: speedcheck\n"
        "    ping_config:\n"
        "      ping: false\n"
        "    tag_multipliers:\n"
        "      cloudflare: 0.5\n"
        "      cn: 2\n"
        "    asn_multipliers:\n"
        "      '13335': 0.8\n",
        encoding="utf-8",
    )
    original = Config.config_file
    try:
        Config.set_config_file(config_file)
        action = Config().actions[0]
        assert isinstance(action, SpeedcheckActionConfig)
        assert list(action.tag_multipliers.items()) == [
            ("cloudflare", 0.5),
            ("cn", 2.0),
        ]
        assert action.asn_multipliers == {13335: 0.8}
        assert not action.ping_config.ping
        assert action.ping_config.port is None
    finally:
        Config.set_config_file(original)
