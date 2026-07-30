from pydantic import BaseModel, FilePath


class GeoDataConfig(BaseModel):
    """geo文件配置"""

    geoip: FilePath | None = None
    geosite: FilePath | None = None
    asn: FilePath | None = None
    ipset: FilePath | None = None
