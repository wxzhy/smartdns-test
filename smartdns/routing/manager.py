from dns.name import Name
from pydantic.networks import IPvAnyAddress

from smartdns.models.geodata import GeoDataConfig
from smartdns.routing.geoip import GeoIP
from smartdns.routing.geosite import GeoSite
from smartdns.routing.ipset import IPSet


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


_geo_manager: GeoManager | None = None


def init_geo_manager(config: GeoDataConfig):
    """初始化GeoManager实例"""
    global _geo_manager
    _geo_manager = GeoManager(config)


def get_geo_manager() -> GeoManager | None:
    """获取GeoManager实例"""
    return _geo_manager
