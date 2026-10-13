# Linux 手动安装

本文不用 `deploy/install.sh`，逐步安装当前源码及随仓库提供的服务文件。命令以首次安装为前提，将程序和配置都放在 `/opt/smartdns`。已有部署时不要直接重复复制或覆盖配置；先检查现有文件并备份。systemd 示例使用动态用户，要求 systemd 247 或更新版本；Debian/Ubuntu 的 SysV `init.d` 示例仍使用固定用户和 `start-stop-daemon`。OpenWrt 的 procd 请参阅[单独的安装说明](openwrt-installation.md)。

## 1. 准备环境和源码

准备系统中可执行、且非 root 服务进程也能访问的 Python 3.14，以及 [`uv`](https://docs.astral.sh/uv/getting-started/installation/)。以下命令在 Linux 的仓库根目录执行，后续代码块沿用同一终端中的 `SRC` 变量：

```sh
cd /path/to/smartdns-test
SRC=$(pwd -P)
command -v python3.14
command -v uv
python3.14 --version
```

本项目没有声明 `[build-system]`，`uv sync` 只安装依赖，不会把 `smartdns` 源码安装为 Python 包。因此下面会复制源码，服务也必须以 `/opt/smartdns` 为工作目录。不要用 `uv run` 作为服务启动命令，以免服务启动时尝试修改由 root 管理的虚拟环境。

## 2. 复制运行文件

```sh
sudo install -d -m 0755 /opt/smartdns
sudo cp -R "$SRC/smartdns" /opt/smartdns/
sudo install -m 0644 "$SRC/pyproject.toml" /opt/smartdns/pyproject.toml
sudo install -m 0644 "$SRC/uv.lock" /opt/smartdns/uv.lock
sudo install -m 0644 "$SRC/README.md" /opt/smartdns/README.md
sudo chmod -R a+rX,go-w /opt/smartdns/smartdns
```

如果配置引用 `tags/output/...` 的 Geo 数据，复制原始输入、转换器及 MaxMind DB。不要从另一架构复制 `geosite.trie` 或 `geoip.radix`；前者由 MARISA-Trie 生成，后者是 py-radix 对象的 pickle，下一步会在目标设备重新生成。

```sh
if [ -f "$SRC/tags/geosite.dat" ]; then
    sudo install -d -m 0755 /opt/smartdns/tags /opt/smartdns/utils/mihomo/component/geodata/router
    sudo install -m 0644 "$SRC/tags/geosite.dat" /opt/smartdns/tags/geosite.dat
    sudo cp -R "$SRC/tags/geosite" "$SRC/tags/geoip" /opt/smartdns/tags/
    sudo install -m 0644 "$SRC/utils/__init__.py" /opt/smartdns/utils/__init__.py
    sudo install -m 0644 "$SRC/utils/convert.py" /opt/smartdns/utils/convert.py
    sudo install -m 0644 "$SRC/utils/message_pool.py" /opt/smartdns/utils/message_pool.py
    for relative in utils/mihomo/__init__.py utils/mihomo/component/__init__.py \
        utils/mihomo/component/geodata/__init__.py \
        utils/mihomo/component/geodata/router/__init__.py; do
        sudo install -m 0644 "$SRC/$relative" "/opt/smartdns/$relative"
    done
fi
sudo install -d -m 0755 /opt/smartdns/tags/output
for database in geoip.metadb asn.mmdb; do
    if [ -f "$SRC/tags/output/$database" ]; then
        sudo install -m 0644 "$SRC/tags/output/$database" \
            "/opt/smartdns/tags/output/$database"
    fi
done
```

若不使用 Geo 数据，可跳过这段命令。没有源文件却启用了对应 `geodata` 字段时，配置校验会失败。服务使用 `/opt/smartdns` 作为工作目录，因此相对数据路径也从这里解析。

## 3. 安装锁定的运行依赖

```sh
UV=$(command -v uv)
PYTHON=$(command -v python3.14)
(cd /opt/smartdns && sudo "$UV" sync --locked --no-dev --python "$PYTHON")
sudo chmod -R a+rX,go-w /opt/smartdns/.venv
if [ -f /opt/smartdns/tags/geosite.dat ]; then
    (cd /opt/smartdns && sudo /opt/smartdns/.venv/bin/python -m utils.convert \
        --geodata-path tags/geosite.dat --tag-path tags --output-path tags/output)
    sudo chmod -R a+rX,go-w /opt/smartdns/tags /opt/smartdns/utils
fi
```

`--locked` 会在 `pyproject.toml` 与 `uv.lock` 不一致时停止，`--no-dev` 不安装开发依赖，详见 [uv 锁定与同步说明](https://docs.astral.sh/uv/concepts/projects/sync/)。命令完成后，运行解释器应位于 `/opt/smartdns/.venv/bin/python`。若安装的 Python 位于某个用户无权进入的私人目录，服务用户将无法运行该解释器；应改用系统可访问的 Python 路径重新安装虚拟环境。

## 4. 放置配置并检查权限

下面使用仅监听本机 `127.0.0.1:5335` 的最小配置；实际部署可将源文件替换成自己的配置。此命令会覆盖目标配置，若 `/opt/smartdns/config.yaml` 已存在，请先检查和备份。先按 systemd 的方式将配置仅留给 root 读取；选择 SysV 时再按第 5 节调整权限。

```sh
sudo install -o root -g root -m 0600 \
    "$SRC/deploy/config.yaml" /opt/smartdns/config.yaml
```

systemd 单元已包含 `CAP_NET_RAW`（`icmplib` 原始 ICMP socket）及 `CAP_NET_BIND_SERVICE`（低端口绑定）。

先以 root 检查配置内容及引用是否有效；systemd 启动时会把该文件复制为动态用户可读取的只读凭据：

```sh
cd /opt/smartdns
sudo /opt/smartdns/.venv/bin/python - <<'PY'
from pathlib import Path
from smartdns.models.config import Config

Config.set_config_file(Path('/opt/smartdns/config.yaml'))
config = Config()
print(f'OK: {len(config.listeners)} listeners, {len(config.nameservers)} nameservers')
PY
```

## 5. 选择一种服务管理方式

### systemd

先执行 `systemctl --version`，确认版本不低于 247。单位文件中的 `DynamicUser=yes` 会在启动时分配 `smartdns` 用户和组，无需手动 `useradd` 或 `groupadd`；`StateDirectory=smartdns` 负责私有状态目录。`LoadCredential=` 将 root 私有的配置副本交给服务，服务从 `${CREDENTIALS_DIRECTORY}/config.yaml` 读取它；配置文件应小于 1 MB。配置文件更新后必须重启服务。若系统中已经存在静态 `smartdns` 用户，systemd 会复用该用户，原有账户不会被自动删除。

```sh
sudo install -m 0644 "$SRC/deploy/smartdns.service" \
    /etc/systemd/system/smartdns.service
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/smartdns.service
sudo systemctl enable --now smartdns
systemctl status smartdns --no-pager
journalctl -u smartdns -n 50 --no-pager
```

服务以动态 `smartdns` 用户运行，工作目录仍为 `/opt/smartdns`，因此相对 Geo 数据路径不变。若改用 53 端口，先检查它没有被其他 DNS 服务占用。原始 ICMP 测速使用 `CAP_NET_RAW`；若确定只使用非特权 ICMP 或 TCP 测速，可按需在本地覆盖该 capability。解释器及其链接目标、源码和 Geo 数据必须允许动态用户读取。

### Debian/Ubuntu 的 SysV init.d

此示例以固定 `smartdns` 用户运行，没有低端口绑定权限。监听器必须使用不低于 1024 的端口，默认的 5335 符合要求。安装前确保系统提供 `start-stop-daemon`、`update-rc.d`、`getent`、`useradd`、`groupadd`、`runuser` 和 `nologin`。只有选择这条路径时才执行以下用户创建和权限调整命令：

```sh
getent group smartdns >/dev/null || sudo groupadd --system smartdns
if ! id -u smartdns >/dev/null 2>&1; then
    sudo useradd --system --gid smartdns --home-dir /var/lib/smartdns \
        --no-create-home --shell "$(command -v nologin)" smartdns
fi
id -nG smartdns  # 输出应包含 smartdns 组
sudo install -d -o smartdns -g smartdns -m 0750 /var/lib/smartdns
sudo chown root:smartdns /opt/smartdns/config.yaml
sudo chmod 0640 /opt/smartdns/config.yaml
cd /opt/smartdns
sudo -u smartdns /opt/smartdns/.venv/bin/python - <<'PY'
from pathlib import Path
from smartdns.models.config import Config

Config.set_config_file(Path('/opt/smartdns/config.yaml'))
Config()
print('Configuration readable by the smartdns user.')
PY
```

```sh
if [ ! -e /var/log/smartdns.log ]; then
    sudo install -o smartdns -g smartdns -m 0640 /dev/null /var/log/smartdns.log
fi
sudo install -m 0755 "$SRC/deploy/smartdns.init" /etc/init.d/smartdns
sudo update-rc.d smartdns defaults
sudo service smartdns start
sudo service smartdns status
sudo tail -n 50 /var/log/smartdns.log
```

`init.d` 示例将输出写入 `/var/log/smartdns.log`。长期运行时请配置日志轮转。它按专用用户和 Python 可执行文件识别进程，不要用该用户运行其他 Python 服务。

## 6. 验证解析与后续修改

若机器装有 `dig`，可对默认配置分别检查 UDP 和 TCP：

```sh
dig @127.0.0.1 -p 5335 example.org A
dig +tcp @127.0.0.1 -p 5335 example.org A
```

默认配置将查询转发给 `1.1.1.1:53`，因此上述解析还依赖主机到上游的网络连通性。修改 `/opt/smartdns/config.yaml` 后，用 `sudo systemctl restart smartdns` 或 `sudo service smartdns restart` 重启对应服务，并查看状态与日志。完整配置字段见 [`configuration.md`](configuration.md)。
