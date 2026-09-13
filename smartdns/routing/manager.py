from typing import TYPE_CHECKING

from smartdns.routing.geoip import GeoIP
from smartdns.routing.geosite import GeoSite
from smartdns.routing.ipset import IPSet

if TYPE_CHECKING:
    from dns.name import Name
    from pydantic.networks import IPvAnyAddress

    from smartdns.models.geodata import GeoDataConfig


class GeoManager:
    def __init__(
        self,
        config: GeoDataConfig,
    ):
        """创建GeoManager实例"""
        self.geoip: GeoIP | None = None
        self.geosite: GeoSite | None = None
        self.ipset: IPSet | None = None
        if config.geoip is not None or config.asn is not None:
            self.geoip = GeoIP()
            self.geoip.load(config.geoip, config.asn)
        if config.geosite is not None:
            self.geosite = GeoSite()
            self.geosite.load(config.geosite)
        if config.ipset is not None:
            self.ipset = IPSet()
            self.ipset.load(config.ipset)

    def lookup_ip(self, ip: str | IPvAnyAddress) -> tuple[set[str], int | None]:
        """查找IP对应的国家和ASN"""
        tags = set()
        asn = None
        if self.geoip is not None:
            tags, asn = self.geoip.lookup(ip)
        if self.ipset is not None:
            tags.update(self.ipset.lookup(ip))
        return tags, asn

    def lookup_domain(self, domain: str | Name) -> set[str]:
        """查找域名对应的标签"""
        tags = set()
        if self.geosite is not None:
            tags = self.geosite.lookup(domain)
        return tags

    def close(self) -> None:
        """释放全部 Geo 数据映射和文件句柄。"""
        for component in (self.geoip, self.geosite, self.ipset):
            if component is not None:
                component.close()
        self.geoip = None
        self.geosite = None
        self.ipset = None


_geo_manager: GeoManager | None = None


def init_geo_manager(config: GeoDataConfig):
    """初始化GeoManager实例"""
    global _geo_manager  # noqa: PLW0603  模块级单例，进程内唯一
    previous = _geo_manager
    _geo_manager = GeoManager(config)
    if previous is not None:
        previous.close()


def close_geo_manager() -> None:
    """关闭并清空进程级 GeoManager。"""
    global _geo_manager  # noqa: PLW0603  模块级单例，进程内唯一
    manager = _geo_manager
    _geo_manager = None
    if manager is not None:
        manager.close()


def get_geo_manager() -> GeoManager | None:
    """获取GeoManager实例"""
    return _geo_manager
