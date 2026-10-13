#!/bin/sh
# 从当前源码目录首次安装到固定路径；不覆盖既有应用或服务配置。
set -eu
umask 022

usage() {
    echo "Usage: sudo sh deploy/install.sh {systemd|initd} [config.yaml]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
case "$1" in
    systemd)
        SERVICE_FILE=/etc/systemd/system/smartdns.service
        ;;
    initd)
        SERVICE_FILE=/etc/init.d/smartdns
        ;;
    *) usage ;;
esac
MODE=$1
SOURCE_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
CONFIG_SOURCE=${2:-"$SOURCE_DIR/deploy/config.yaml"}
APP_DIR=/opt/smartdns
RUN_USER=smartdns

[ "$(uname -s)" = Linux ] || { echo "This installer is for Linux." >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run this installer as root." >&2; exit 1; }
[ -f "$CONFIG_SOURCE" ] || { echo "Config file not found: $CONFIG_SOURCE" >&2; exit 1; }
[ ! -e "$APP_DIR" ] && [ ! -L "$APP_DIR" ] || {
    echo "$APP_DIR already exists; this example installer only performs a fresh install." >&2
    exit 1
}
[ ! -e "$SERVICE_FILE" ] && [ ! -L "$SERVICE_FILE" ] || {
    echo "$SERVICE_FILE already exists; refusing to overwrite it." >&2
    exit 1
}

UV=$(command -v uv) || { echo "Install uv and add it to root's PATH first." >&2; exit 1; }
PYTHON=$(command -v python3.14) || {
    echo "Install a system-accessible Python 3.14 first." >&2
    exit 1
}
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 14)'
if [ "$MODE" = systemd ]; then
    command -v systemctl >/dev/null || { echo "systemctl is required." >&2; exit 1; }
    command -v systemd-analyze >/dev/null || {
        echo "systemd-analyze is required." >&2
        exit 1
    }
    SYSTEMD_VERSION=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
    case "$SYSTEMD_VERSION" in
        ''|*[!0-9]*) echo "Cannot determine the systemd version." >&2; exit 1 ;;
    esac
    [ "$SYSTEMD_VERSION" -ge 247 ] || {
        echo "The DynamicUser/LoadCredential example requires systemd 247 or newer." >&2
        exit 1
    }
else
    command -v start-stop-daemon >/dev/null || {
        echo "The init.d example requires Debian's start-stop-daemon." >&2
        exit 1
    }
    command -v getent >/dev/null || { echo "getent is required." >&2; exit 1; }
    command -v runuser >/dev/null || { echo "runuser is required." >&2; exit 1; }
    command -v useradd >/dev/null || { echo "useradd is required." >&2; exit 1; }
    command -v groupadd >/dev/null || { echo "groupadd is required." >&2; exit 1; }
    if ! getent group "$RUN_USER" >/dev/null; then
        groupadd --system "$RUN_USER"
    fi
    if ! id -u "$RUN_USER" >/dev/null 2>&1; then
        NOLOGIN=$(command -v nologin) || { echo "nologin is required." >&2; exit 1; }
        useradd --system --gid "$RUN_USER" --home-dir /var/lib/smartdns \
            --no-create-home --shell "$NOLOGIN" "$RUN_USER"
    fi
    if ! id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx "$RUN_USER"; then
        echo "Existing $RUN_USER user must belong to the $RUN_USER group." >&2
        exit 1
    fi
fi

APP_CREATED=0
SERVICE_CREATED=0
cleanup_on_error() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        echo "Installation failed; removing the new application and service files." >&2
        if [ "$SERVICE_CREATED" -eq 1 ]; then
            rm -f "$SERVICE_FILE"
        fi
        if [ "$APP_CREATED" -eq 1 ]; then
            rm -rf "$APP_DIR"
        fi
    fi
    exit "$status"
}
trap cleanup_on_error EXIT

mkdir -m 0755 "$APP_DIR"
APP_CREATED=1
cp -R "$SOURCE_DIR/smartdns" "$APP_DIR/"
install -m 0644 "$SOURCE_DIR/pyproject.toml" "$APP_DIR/pyproject.toml"
install -m 0644 "$SOURCE_DIR/uv.lock" "$APP_DIR/uv.lock"
install -m 0644 "$SOURCE_DIR/README.md" "$APP_DIR/README.md"
GEODATA_BUILD=0
if [ -f "$SOURCE_DIR/tags/geosite.dat" ]; then
    # Copy source inputs and the generated protobuf model, never another
    # machine's MARISA trie or py-radix pickle. Rebuild after uv sync.
    install -d -m 0755 "$APP_DIR/tags/geosite" "$APP_DIR/tags/geoip" \
        "$APP_DIR/utils/mihomo/component/geodata/router"
    install -m 0644 "$SOURCE_DIR/tags/geosite.dat" "$APP_DIR/tags/geosite.dat"
    install -m 0644 "$SOURCE_DIR/utils/__init__.py" "$APP_DIR/utils/__init__.py"
    install -m 0644 "$SOURCE_DIR/utils/convert.py" "$APP_DIR/utils/convert.py"
    install -m 0644 "$SOURCE_DIR/utils/message_pool.py" "$APP_DIR/utils/message_pool.py"
    for relative in utils/mihomo/__init__.py \
        utils/mihomo/component/__init__.py \
        utils/mihomo/component/geodata/__init__.py \
        utils/mihomo/component/geodata/router/__init__.py; do
        install -m 0644 "$SOURCE_DIR/$relative" "$APP_DIR/$relative"
    done
    for input in "$SOURCE_DIR"/tags/geosite/*.txt; do
        [ -f "$input" ] || continue
        install -m 0644 "$input" "$APP_DIR/tags/geosite/$(basename "$input")"
    done
    for input in "$SOURCE_DIR"/tags/geoip/*.txt; do
        [ -f "$input" ] || continue
        install -m 0644 "$input" "$APP_DIR/tags/geoip/$(basename "$input")"
    done
    GEODATA_BUILD=1
fi
if [ -d "$SOURCE_DIR/tags/output" ]; then
    install -d -m 0755 "$APP_DIR/tags/output"
    for database in geoip.metadb asn.mmdb; do
        if [ -f "$SOURCE_DIR/tags/output/$database" ]; then
            install -m 0644 "$SOURCE_DIR/tags/output/$database" \
                "$APP_DIR/tags/output/$database"
        fi
    done
fi
chmod -R a+rX,go-w "$APP_DIR/smartdns"

(
    cd "$APP_DIR"
    "$UV" sync --locked --no-dev --python "$PYTHON"
    if [ "$GEODATA_BUILD" -eq 1 ]; then
        "$APP_DIR/.venv/bin/python" -m utils.convert \
            --geodata-path tags/geosite.dat --tag-path tags \
            --output-path tags/output
    fi
)
chmod -R a+rX,go-w "$APP_DIR/.venv"
[ ! -d "$APP_DIR/tags" ] || chmod -R a+rX,go-w "$APP_DIR/tags"
[ ! -d "$APP_DIR/utils" ] || chmod -R a+rX,go-w "$APP_DIR/utils"

if [ "$MODE" = systemd ]; then
    CONFIG_GROUP=root
    CONFIG_FILE_MODE=0600
else
    CONFIG_GROUP=$RUN_USER
    CONFIG_FILE_MODE=0640
fi
install -o root -g "$CONFIG_GROUP" -m "$CONFIG_FILE_MODE" \
    "$CONFIG_SOURCE" "$APP_DIR/config.yaml"
if [ "$MODE" = systemd ]; then
    CONFIG_BYTES=$(wc -c < "$APP_DIR/config.yaml")
    [ "$CONFIG_BYTES" -le 1000000 ] || {
        echo "This installer limits config.yaml to 1 MB for LoadCredential." >&2
        exit 1
    }
fi
if [ "$MODE" = initd ]; then
    install -d -o "$RUN_USER" -g "$RUN_USER" -m 0750 /var/lib/smartdns
fi

(
    cd "$APP_DIR"
    if [ "$MODE" = systemd ]; then
        set -- env SMARTDNS_INSTALL_MODE="$MODE" "$APP_DIR/.venv/bin/python" -
    else
        set -- runuser -u "$RUN_USER" -- env SMARTDNS_INSTALL_MODE="$MODE" \
            "$APP_DIR/.venv/bin/python" -
    fi
    "$@" <<'PY'
import os
from pathlib import Path

from smartdns.models.config import Config

Config.set_config_file(Path('/opt/smartdns/config.yaml'))
config = Config()
if os.environ['SMARTDNS_INSTALL_MODE'] == 'initd' and any(
    listener.port < 1024 for listener in config.listeners
):
    raise SystemExit('init.d example runs unprivileged; listener ports must be >= 1024')
print('Configuration references validated.')
PY
)

if [ "$MODE" = systemd ]; then
    SERVICE_CREATED=1
    install -m 0644 "$SOURCE_DIR/deploy/smartdns.service" "$SERVICE_FILE"
    systemd-analyze verify "$SERVICE_FILE"
    systemctl daemon-reload
    echo "Installed. Review $APP_DIR/config.yaml, then run: systemctl enable --now smartdns"
else
    if [ ! -e /var/log/smartdns.log ]; then
        install -o "$RUN_USER" -g "$RUN_USER" -m 0640 /dev/null /var/log/smartdns.log
    fi
    SERVICE_CREATED=1
    install -m 0755 "$SOURCE_DIR/deploy/smartdns.init" "$SERVICE_FILE"
    echo "Installed. Review $APP_DIR/config.yaml, then run: update-rc.d smartdns defaults && service smartdns start"
fi
