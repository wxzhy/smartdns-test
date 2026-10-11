from ipaddress import IPv4Address
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from smartdns.actions.base import BaseAction
from smartdns.actions.fallback import FallbackAction
from smartdns.actions.filter import FilterAction
from smartdns.actions.https import HTTPSAction
from smartdns.actions.log import LogAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.actions.static import StaticAction
from smartdns.models import action as models
from smartdns.models.config import Config


def test_nested_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Config(
            actions=[
                {
                    "name": "https",
                    "type": "https",
                    "match_name": {},
                    "match_ip": {},
                    "ech": "wrong-field.example",
                }
            ]
        )


def test_http_listener_is_rejected_during_config_load() -> None:
    with pytest.raises(ValidationError, match="尚未实现 HTTP Listener"):
        Config(
            listeners=[
                {
                    "name": "doh",
                    "type": "http",
                    "host": IPv4Address("127.0.0.1"),
                    "port": 8053,
                }
            ]
        )


def test_invalid_and_forward_resolver_references_are_rejected() -> None:
    with pytest.raises(ValidationError, match="previous resolvers"):
        Config(
            resolvers=[
                {
                    "name": "race",
                    "type": "concurrent",
                    "resolvers": ["later"],
                },
                {
                    "name": "later",
                    "type": "aiodns",
                    "nameservers": ["1.1.1.1"],
                },
            ]
        )


def test_aiodns_nameserver_must_be_an_ip_address() -> None:
    with pytest.raises(ValidationError):
        Config(
            resolvers=[
                {
                    "name": "direct",
                    "type": "aiodns",
                    "nameservers": ["udp-by-name"],
                }
            ]
        )


def test_aiodns_ecs_field_is_rejected() -> None:
    """aiodns 不支持 ECS（pycares 无法注入该选项），字段已删除；误配应报错。"""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Config(
            resolvers=[
                {
                    "name": "direct",
                    "type": "aiodns",
                    "nameservers": ["1.1.1.1"],
                    "ecs": "203.0.113.0/24",
                }
            ]
        )


def _action_config(name: str, action_type: str) -> dict[str, object]:
    extra: dict[str, dict[str, object]] = {
        "log": {"text": "log"},
        "replace": {"match_name": {}},
        "https": {"match_name": {}, "match_ip": {}, "add_ech": False},
    }
    return {"name": name, "type": action_type, **extra.get(action_type, {})}


@pytest.mark.parametrize(
    ("action_type", "field"),
    [
        ("filter", "after"),
        ("replace", "after"),
        ("static", "after"),
        ("https", "before"),
        ("speedcheck", "before"),
    ],
)
def test_route_action_in_unsupported_phase_is_rejected(
    action_type: str, field: str
) -> None:
    with pytest.raises(ValidationError, match=f"放在 {field} 阶段不会生效"):
        Config(
            actions=[_action_config("act", action_type)],
            routing=[{"name": "rule", field: ["act"]}],
        )


@pytest.mark.parametrize("action_type", ["static", "log", "https", "fallback"])
def test_resolver_action_in_unsupported_phase_is_rejected(action_type: str) -> None:
    with pytest.raises(ValidationError, match="放在 resolver 阶段不会生效"):
        Config(
            actions=[_action_config("act", action_type)],
            resolvers=[
                {"name": "up", "type": "aiodns", "nameservers": ["192.0.2.1"]},
                {
                    "name": "race",
                    "type": "concurrent",
                    "resolvers": ["up"],
                    "actions": ["act"],
                },
            ],
        )


def test_declared_phases_match_implemented_hooks() -> None:
    pairs = [
        (LogAction, models.LogActionConfig),
        (StaticAction, models.StaticActionConfig),
        (ReplaceAction, models.ReplaceActionConfig),
        (HTTPSAction, models.HTTPSActionConfig),
        (FallbackAction, models.FallbackActionConfig),
        (SpeedcheckAction, models.SpeedcheckActionConfig),
        (FilterAction, models.FilterActionConfig),
    ]
    hooks = {
        "before": ("on_request",),
        "after": ("on_response", "on_subquery"),
        "resolver": ("on_resolver",),
    }
    for action_cls, config_cls in pairs:
        implemented = {
            phase
            for phase, names in hooks.items()
            if any(getattr(action_cls, n) is not getattr(BaseAction, n) for n in names)
        }
        assert implemented == config_cls.phases, action_cls.__name__


@pytest.mark.parametrize(
    ("nameservers", "actions"),
    [
        (
            [
                {
                    "name": "doh",
                    "type": "curl",
                    "url": "https://dns.example/dns-query",
                    "ech": "crypto.example",
                }
            ],
            [],
        ),
        ([], [{"name": "https", "type": "https", "match_name": {}, "match_ip": {}}]),
    ],
    ids=["curl-ech-domain", "https-add-ech"],
)
def test_ech_users_require_client_resolver(
    nameservers: list[dict[str, object]], actions: list[dict[str, object]]
) -> None:
    with pytest.raises(ValidationError, match=r"需要 client\.resolver"):
        Config(nameservers=nameservers, actions=actions)
    resolver = {"name": "boot", "type": "aiodns", "nameservers": ["192.0.2.1"]}
    Config(nameservers=nameservers, actions=actions, client={"resolver": resolver})


@pytest.mark.parametrize(
    "path",
    ["config.yaml", "config-cernet.yaml", "example.yaml", "deploy/config.yaml"],
)
def test_shipped_configs_pass_validation(path: str) -> None:
    root = Path(__file__).resolve().parents[2]
    data = yaml.safe_load((root / path).read_text(encoding="utf-8"))
    # Geo 数据文件由目标设备生成，不在仓库中；其余引用与阶段均须合法。
    data.pop("geodata", None)
    Config(**data)
