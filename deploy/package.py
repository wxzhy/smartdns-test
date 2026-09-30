"""Build a source deployment ZIP without architecture-dependent Geo caches."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
STATIC_FILES = (
    "README.md",
    "main.py",
    "pyproject.toml",
    "uv.lock",
    "config.yaml",
    "config-cernet.yaml",
    "example.yaml",
    "deploy/config.yaml",
    "deploy/install.sh",
    "deploy/package.py",
    "deploy/smartdns.init",
    "deploy/smartdns.openwrt.capabilities.json",
    "deploy/smartdns.openwrt.init",
    "deploy/smartdns.service",
    "docs/architecture.md",
    "docs/configuration.md",
    "docs/manual-installation.md",
    "docs/openwrt-installation.md",
    "utils/__init__.py",
    "utils/convert.py",
    "utils/message_pool.py",
    "tags/geosite.dat",
    "tags/output/geoip.metadb",
    "tags/output/asn.mmdb",
)
GENERATED = frozenset(
    {
        "tags/output/geosite.trie",
        "tags/output/geoip.radix",
        "tags/output/geosite.json",
    }
)
EXECUTABLE = frozenset(
    {
        "deploy/install.sh",
        "deploy/smartdns.init",
        "deploy/smartdns.openwrt.init",
    }
)


def source_files() -> list[str]:
    paths = {Path(name) for name in STATIC_FILES}
    for directory, pattern in (
        ("smartdns", "*.py"),
        ("utils/mihomo", "*.py"),
        ("tags/geosite", "*.txt"),
        ("tags/geoip", "*.txt"),
    ):
        paths.update((ROOT / directory).rglob(pattern))
    names = sorted(
        path.relative_to(ROOT).as_posix() if path.is_absolute() else path.as_posix()
        for path in paths
    )
    for name in names:
        if not (ROOT / name).is_file():
            raise FileNotFoundError(ROOT / name)
    if GENERATED.intersection(names):
        raise ValueError("Generated Geo caches must not be packaged")
    return names


def add_file(archive: ZipFile, name: str, contents: bytes) -> None:
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    mode = (
        0o100755 if any(name.endswith(f"/{path}") for path in EXECUTABLE) else 0o100644
    )
    info.external_attr = mode << 16
    info.compress_type = ZIP_DEFLATED
    archive.writestr(info, contents)


def main() -> None:
    commit = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True
    ).strip()
    date = datetime.now(UTC).strftime("%Y%m%d")
    package = f"smartdns-deploy-{date}-{commit}-source"
    deployment = f"""SmartDNS source deployment package ({commit})

This ZIP contains source code, Geo source inputs, and portable MaxMind DB files.
It does not contain a Python environment or generated geosite.trie,
geoip.radix, or geosite.json. Build these with the target's Python and native
dependencies after uv sync, before starting a geodata-enabled configuration:

  cd /opt/smartdns-python
  .venv/bin/python -m utils.convert --geodata-path tags/geosite.dat \\
    --tag-path tags --output-path tags/output

For OpenWrt, follow docs/openwrt-installation.md. Keep dnsmasq on a working
independent upstream until direct DNS queries to SmartDNS pass. For an existing
installation, copy only the required files and preserve config.yaml and any
newer local MaxMind DBs. Review the bundled config.yaml's network-specific
DNS endpoints and proxy addresses for the target network before deployment.

For Linux systemd or init.d, see docs/manual-installation.md or use
deploy/install.sh for a fresh installation. Install Python and native
dependencies for the target architecture; never copy a .venv from another
platform. DNSCrypt requires a loadable libsodium library.
"""

    contents = {name: (ROOT / name).read_bytes() for name in source_files()}
    contents["DEPLOYMENT.txt"] = deployment.encode("utf-8")
    manifest = {
        "format": 1,
        "source_commit": commit,
        "rebuild_on_target": sorted(GENERATED),
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            for name, data in sorted(contents.items())
        },
    }
    contents["MANIFEST.json"] = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")

    DIST.mkdir(exist_ok=True)
    target = DIST / f"{package}.zip"
    temp = target.with_suffix(".zip.tmp")
    with ZipFile(temp, "w") as archive:
        for name, data in sorted(contents.items()):
            add_file(archive, f"{package}/{name}", data)
    temp.replace(target)

    with ZipFile(target) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(contents)
        for name, metadata in manifest["files"].items():
            data = archive.read(f"{package}/{name}")
            assert len(data) == metadata["size"]
            assert hashlib.sha256(data).hexdigest() == metadata["sha256"]
        assert not any(f"{package}/{name}" in archive.namelist() for name in GENERATED)
    print(f"{target} sha256={hashlib.sha256(target.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
