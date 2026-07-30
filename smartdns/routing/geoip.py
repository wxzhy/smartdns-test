from pathlib import Path

from maxminddb_rust import MODE_MMAP_EXT, Reader
from pydantic.networks import IPvAnyAddress


class GeoIP:
    """IP地理位置数据库"""

    def __init__(self):
        self._geoip: Reader | None = None
        self._asn: Reader | None = None

    def load(self, geoip_path: Path | None, asn_path: Path | None):
        """加载GeoIP数据库"""
        if geoip_path is not None and geoip_path.exists():
            self._geoip = Reader(database=geoip_path, mode=MODE_MMAP_EXT)
        if asn_path is not None and asn_path.exists():
            self._asn = Reader(database=asn_path, mode=MODE_MMAP_EXT)

    def lookup(self, ip: str | IPvAnyAddress) -> tuple[set[str], int | None]:
        """查找IP对应的国家和ASN"""
        country = set()
        asn = None
        if self._geoip is not None:
            country_info = self._geoip.get(ip)
            if country_info is not None:
                country.update([country_info.country.iso_code])
        if self._asn is not None:
            asn_info = self._asn.get(ip)
            if asn_info is not None:
                asn = asn_info.autonomous_system_number
        return country, asn
