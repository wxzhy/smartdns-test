"""Phase 6：GeoIP 记录形状提取回归测试。

修复前：lookup 只处理 str/list 记录，标准 MaxMind 的 dict 形状
（``{"country": {"iso_code": ...}}``）被静默丢弃 → geoip 匹配静默失效。
修复后：显式兼容 str/list/dict 形状，未识别形状告警。
"""

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from smartdns.routing.geoip import GeoIP

if TYPE_CHECKING:
    from maxminddb import Reader


def test_extract_country_dict_shape() -> None:
    assert GeoIP._extract_country({"country": {"iso_code": "US"}}) == {"US"}


def test_extract_country_str() -> None:
    assert GeoIP._extract_country("CN") == {"CN"}


def test_extract_country_list() -> None:
    assert GeoIP._extract_country(["CN", "HK"]) == {"CN", "HK"}


def test_extract_country_none_is_empty() -> None:
    assert GeoIP._extract_country(None) == set()


def test_extract_country_unknown_shape_is_empty() -> None:
    assert GeoIP._extract_country({"unexpected": 1}) == set()


def test_close_releases_both_readers_and_is_idempotent() -> None:
    class _ClosableReader:
        closes = 0

        def close(self) -> None:
            self.closes += 1

    country = _ClosableReader()
    asn = _ClosableReader()
    geoip = GeoIP()
    geoip._geoip = cast("Reader", country)
    geoip._asn = cast("Reader", asn)

    geoip.close()
    geoip.close()

    assert country.closes == 1
    assert asn.closes == 1
    assert geoip._geoip is None
    assert geoip._asn is None


def test_load_opens_both_databases_and_reads_metadata(tmp_path, monkeypatch) -> None:
    opened: list[str] = []

    class _Reader:
        def __init__(self, path) -> None:
            self.path = path

        def metadata(self) -> SimpleNamespace:
            return SimpleNamespace(
                database_type="GeoLite2-Country", node_count=10, build_epoch=0
            )

        def close(self) -> None:
            opened.remove(self.path.name)

    def fake_open(database, mode) -> _Reader:
        opened.append(database.name)
        return _Reader(database)

    for name in ("geoip.mmdb", "asn.mmdb"):
        (tmp_path / name).write_bytes(b"")
    monkeypatch.setattr("smartdns.routing.geoip.open_database", fake_open)
    geoip = GeoIP()
    geoip.load(tmp_path / "geoip.mmdb", tmp_path / "asn.mmdb")
    assert opened == ["geoip.mmdb", "asn.mmdb"]
    geoip.close()
    assert opened == []
