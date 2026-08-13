from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

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
