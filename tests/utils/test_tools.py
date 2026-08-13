import importlib
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from utils.convert import app, convert

if TYPE_CHECKING:
    from pathlib import Path


def test_fetch_ip_import_has_no_file_side_effect(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    importlib.reload(importlib.import_module("utils.fetch_ip"))
    assert list(tmp_path.iterdir()) == []


def test_convert_first_run_creates_all_outputs(tmp_path: Path) -> None:
    tags = tmp_path / "tags"
    tags.mkdir()
    output = tmp_path / "output"
    convert(tmp_path / "missing.dat", tags, output)
    assert {path.name for path in output.iterdir()} == {
        "geosite.json",
        "geosite.trie",
        "geoip.radix",
    }


def test_convert_cli_preserves_named_options(tmp_path: Path) -> None:
    tags = tmp_path / "tags"
    tags.mkdir()
    output = tmp_path / "output"
    result = CliRunner().invoke(
        app,
        [
            "--geodata-path",
            str(tmp_path / "missing.dat"),
            "--tag-path",
            str(tags),
            "--output-path",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert (output / "geosite.json").is_file()
