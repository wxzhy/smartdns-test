"""MaxMind GeoIP/ASN 查询：把 IP 映射为国家/自定义标签与 ASN。"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger
from maxminddb import MODE_MMAP_EXT, Reader, open_database

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic.networks import IPvAnyAddress


class GeoIP:
    """IP地理位置数据库"""

    def __init__(self):
        self._geoip: Reader | None = None
        self._asn: Reader | None = None

    def load(self, geoip_path: Path | None, asn_path: Path | None):
        """加载 GeoIP（国家/标签）与 ASN 两个 MaxMind 数据库，均可缺省。"""
        if geoip_path is not None and geoip_path.exists():
            self._geoip = self._open(geoip_path)
        if asn_path is not None and asn_path.exists():
            self._asn = self._open(asn_path)

    @staticmethod
    def _open(path: Path) -> Reader:
        reader = open_database(database=path, mode=MODE_MMAP_EXT)
        metadata = reader.metadata()
        logger.info(
            "从{}加载 MaxMind 数据库成功：类型 {}，记录节点 {}，构建于 {}",
            path,
            metadata.database_type,
            metadata.node_count,
            datetime.fromtimestamp(metadata.build_epoch, UTC).date(),
        )
        return reader

    @staticmethod
    def _extract_country(record: object) -> set[str]:
        """从多种 MaxMind 记录形状中提取国家/标签集合。

        兼容自定义库的 str/list 形状与标准 MaxMind 的 dict 形状
        （``{"country": {"iso_code": ...}}``）；未识别形状告警而非静默失效。
        """
        match record:
            case None:
                return set()
            case str():
                return {record}
            case list():
                return {str(item) for item in record}
            case {"country": {"iso_code": str(code)}}:
                return {code}
            case _:
                logger.warning("GeoIP 记录形状未识别: {!r}", record)
                return set()

    def lookup(self, ip: str | IPvAnyAddress) -> tuple[set[str], int | None]:
        """查找IP对应的国家和ASN"""
        key = str(ip)
        country: set[str] = set()
        asn: int | None = None
        if self._geoip is not None:
            country = self._extract_country(self._geoip.get(key))
        if self._asn is not None:
            asn_info = self._asn.get(key)
            if isinstance(asn_info, dict):
                asn = asn_info.get("autonomous_system_number")
        return country, asn

    def close(self) -> None:
        """关闭 MaxMind mmap reader 并释放文件句柄。"""
        geoip, asn = self._geoip, self._asn
        self._geoip = None
        self._asn = None
        if geoip is not None:
            geoip.close()
        if asn is not None:
            asn.close()
