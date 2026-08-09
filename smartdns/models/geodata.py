from __future__ import annotations

from dns.name import Name
from pydantic import BaseModel, ConfigDict, FilePath, IPvAnyAddress
from pydantic.dataclasses import dataclass

from smartdns.routing.manager import get_geo_manager


class GeoDataConfig(BaseModel):
    """geo文件配置"""

    geoip: FilePath | None = None
    geosite: FilePath | None = None
    asn: FilePath | None = None
    ipset: FilePath | None = None


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class IPInfo:
    """IP 运行时信息。"""

    ip: IPvAnyAddress
    asn: int | None = None
    country: set[str] | None = None
    rtt: float | None = None
    resolver: str | None = None

    @classmethod
    def from_ip(cls, ip: IPvAnyAddress, resolver=None) -> IPInfo:
        """从IP地址创建IPInfo对象"""
        geo_manager = get_geo_manager()
        if not geo_manager:
            return cls(ip=ip)
        country, asn = geo_manager.lookup_ip(str(ip))
        return cls(ip=ip, country=country, asn=asn, resolver=resolver)


@dataclass(slots=True, config=ConfigDict(arbitrary_types_allowed=True))
class NameInfo:
    """域名运行时信息。"""

    name: Name
    country: set[str] | None = None

    @classmethod
    def from_name(cls, name: Name) -> NameInfo:
        """从域名创建NameInfo对象"""
        geo_manager = get_geo_manager()
        if not geo_manager:
            return cls(name=name)
        country = geo_manager.lookup_domain(name)
        return cls(name=name, country=country)
