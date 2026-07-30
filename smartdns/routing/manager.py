
from dns.name import Name
from loguru import logger

from smartdns.models.geodata import GeoDataConfig
from smartdns.routing.geoip import GeoIP
from smartdns.routing.geosite import GeoSite
from smartdns.routing.ipset import IPSet


class GeoManager:
    geoip: GeoIP | None
    geosite: GeoSite | None
    ipset: IPSet | None

    def __init__(self):
        logger.debug("初始化GeoManager")

    @classmethod
    def create(
        cls,
        config: GeoDataConfig,
    ):
        """创建GeoManager实例"""
        if config.geoip is not None or config.asn is not None:
            cls.geoip = GeoIP()
            cls.geoip.load(config.geoip, config.asn)
        if config.geosite is not None:
            cls.geosite = GeoSite()
            cls.geosite.load(config.geosite)
        if config.ipset is not None:
            cls.ipset = IPSet()
            cls.ipset.load(config.ipset)

    @classmethod
    def lookup_ip(cls, ip: str) -> tuple[set[str], int | None]:
        """查找IP对应的国家和ASN"""
        tags = set()
        asn = None
        if cls.geoip is not None:
            tags, asn = cls.geoip.lookup(ip)
        if cls.ipset is not None:
            tags.update(cls.ipset.lookup(ip))
        return tags, asn

    @classmethod
    def lookup_domain(cls, domain: str | Name) -> set[str]:
        """查找域名对应的标签"""
        tags = set()
        if cls.geosite is not None:
            tags = cls.geosite.lookup(domain)
        return tags
