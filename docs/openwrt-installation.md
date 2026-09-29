# OpenWrt 手动安装（procd）

此示例使用独立的 [`deploy/smartdns.openwrt.init`](../deploy/smartdns.openwrt.init)，按 [OpenWrt 的 procd 约定](https://openwrt.org/docs/guide-developer/procd-init-scripts)管理进程。它与 Debian/Ubuntu 的 [`deploy/smartdns.init`](../deploy/smartdns.init) 不通用，也不使用 [`deploy/install.sh`](../deploy/install.sh)。[OpenWrt 软件源中的另一款 `smartdns` 包](https://github.com/openwrt/packages/blob/master/net/smartdns/Makefile)会使用 `/etc/init.d/smartdns` 和 `/etc/smartdns`；本示例将 Python 服务命名为 `smartdns-python`，程序及配置都放在 `/opt/smartdns-python`，避免覆盖它。下列命令假定首次安装、以路由器的 root 用户操作。已有同名文件或目录时，请先检查和备份。

## 1. 确认设备能运行本项目

本项目要求 **Python 3.14 或更新版本**，还依赖 `aiofastnet`、`curl-cffi`、`marisa-trie`、`py-radix` 等原生扩展。先确认路由器的 CPU 架构、OpenWrt 的 musl ABI、可用存储空间，以及可运行的 Python、uv 和对应依赖；普通 Linux 或 Windows 上创建的 `.venv` 不能直接复制到 OpenWrt。若目标平台缺少兼容的解释器、wheel 或编译环境，下面的服务脚本无法弥补这个问题。建议将 `/opt` 放在容量充足、开机时已挂载的持久存储上。

在路由器上检查：

```sh
uname -m
df -h / /tmp
python3.14 --version
uv --version
```

上述命令必须成功；`python3.14` 和 `uv` 的取得方式取决于设备架构和固件软件源。不要让 `uv` 在服务启动时临时下载 Python 或依赖。若使用 DNSCrypt，上游还要求目标系统中有可动态加载的 libsodium。

此服务要求 OpenWrt 的 `procd-ujail`：在 25.12 及更新版本使用 `apk add procd-ujail`，在 24.10 及更早版本使用 `opkg update && opkg install procd-ujail`。确认 `test -x /sbin/ujail` 和 `stat -c '%u:%g:%a' /etc/passwd` 成功；若设备内核或容器环境不允许创建 jail 所需的挂载命名空间，服务会启动失败，应先解决平台限制。

## 2. 建立专用用户并复制文件

OpenWrt 需要 `groupadd`、`useradd` 命令来创建本示例使用的 `smartdnspy` 用户。若未安装，OpenWrt 25.12 及更新版本可用 `apk add shadow-useradd shadow-groupadd`；24.10 及更早版本可用 `opkg update && opkg install shadow-useradd shadow-groupadd`（见 [OpenWrt 软件包管理说明](https://openwrt.org/docs/guide-user/additional-software/managing_packages)）。先确认软件源与固件版本匹配。在路由器上执行：

```sh
groupadd -r smartdnspy
useradd -r -g smartdnspy -M -d /var/run/smartdns-python -s /bin/false smartdnspy
id smartdnspy
```

在源码仓库根目录（开发机）打包并传到路由器；将示例地址换成路由器地址。如果配置需要已生成的地理数据，再把 `tags/output` 加入打包命令。

```sh
tar -czf smartdns-openwrt.tar.gz smartdns pyproject.toml uv.lock README.md deploy/config.yaml deploy/smartdns.openwrt.init deploy/smartdns.openwrt.capabilities.json
scp smartdns-openwrt.tar.gz root@192.168.1.1:/tmp/
```

若路由器的 SSH 服务没有 SFTP 子系统，可尝试 `scp -O` 使用旧式 SCP 协议。

在路由器上解包。已有部署时不要直接覆盖目录或启动脚本。

```sh
mkdir -p /opt/smartdns-python
tar -xzf /tmp/smartdns-openwrt.tar.gz -C /opt/smartdns-python
```

示例配置只在 `127.0.0.1:5335` 监听 UDP/TCP，向 `1.1.1.1:53` 转发，不需要 53 端口权限。启动前确认 5335 未被其他服务占用。自定义配置若引用 `tags/output` 等相对路径，路径从 `/opt/smartdns-python` 解析。服务以普通用户运行，请确保该用户能读取这些文件。与 systemd 示例一样，capability 配置提供 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`，可用于绑定 53 端口及运行特权 ICMP 测速；改用 53 端口前须先解除与 dnsmasq 等服务的端口冲突。

## 3. 在目标平台安装并检查依赖

在路由器上用已确认可用的 Python 和 uv 同步锁定依赖。`--no-python-downloads` 避免 uv 自动下载解释器；如果原生扩展在该平台无法安装，请先解决目标平台的构建/分发问题，再继续部署。

```sh
cd /opt/smartdns-python
UV_CACHE_DIR=/opt/smartdns-python/.uv-cache uv sync --locked --no-dev \
    --no-python-downloads --python "$(command -v python3.14)"
/opt/smartdns-python/.venv/bin/python -c 'import smartdns.main; print("imports OK")'
chown -R root:root /opt/smartdns-python
chmod -R go-w /opt/smartdns-python
chmod 0755 /opt/smartdns-python
cp /opt/smartdns-python/deploy/config.yaml /opt/smartdns-python/config.yaml
chown root:smartdnspy /opt/smartdns-python/config.yaml
chmod 0640 /opt/smartdns-python/config.yaml
chown root:root /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
chmod 0644 /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
```

解释器及其链接目标也必须可由 `smartdnspy` 用户访问；程序目录、虚拟环境和 capability 配置应始终保持 root 拥有且不可由该用户修改。jail 会只读挂载程序目录、解释器实际文件、常见系统库目录、CA 证书及主机解析文件；如果 Python 或原生库放在其他目录，需要把对应目录加入 init 脚本的只读挂载列表。如果上述导入失败，先处理缺失的 Python 包、原生库或 ABI 问题，不要启用服务。

若 DNSCrypt 使用的 libsodium 不在动态库默认搜索路径，可另建 `/opt/smartdns-python/environment`，写入一行 `SMARTDNS_LIBSODIUM_PATH=/绝对路径/libsodium.so`，并执行 `chown root:root /opt/smartdns-python/environment && chmod 0600 /opt/smartdns-python/environment`。init 脚本只读取这个赋值，不执行文件内容；它会拒绝符号链接、非 root:root 0600 文件以及其他配置项，并将该库只读挂载进 jail。启用 DNSCrypt 前，先用相同路径验证 `SMARTDNS_LIBSODIUM_PATH=/绝对路径/libsodium.so /opt/smartdns-python/.venv/bin/python -c 'from smartdns.nameservers._sodium import require_libsodium; require_libsodium()'` 能成功执行。

## 4. 安装并启动 procd 服务

```sh
cp /opt/smartdns-python/deploy/smartdns.openwrt.init /etc/init.d/smartdns-python
chown root:root /etc/init.d/smartdns-python
chmod 0755 /etc/init.d/smartdns-python
/etc/init.d/smartdns-python start
/etc/init.d/smartdns-python status
logread -e smartdns
```

启动脚本让 procd 通过 `ujail` 监管 Python 服务，异常退出后重启；标准输出和错误进入 OpenWrt 日志。隔离配置使用专用用户/组、`no_new_privs`，并将 capability 的五个集合均限制为 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`；不挂载 `/proc`、`/sys` 或 ubus。程序与配置只读，仅 `/var/run/smartdns-python` 对服务可写，并作为 `HOME` 和 `TMPDIR`。该目录在每次启动时创建为 `smartdnspy:smartdnspy`、0700；Python 进程采用与 systemd 示例相同的 `0027` umask。`term_timeout 35` 为被隔离的进程提供 35 秒停止宽限时间；procd 使用 `SIGTERM`，且对 jail 管理进程另有超时，因此总体停止时长不一定等于 systemd 的 `TimeoutStopSec=35`。若需访问程序目录之外的地理数据、证书或库，先按最小范围补充只读挂载。修改 `/opt/smartdns-python/config.yaml`、capability 配置或 `environment` 后用 `/etc/init.d/smartdns-python restart`，停用自启动用 `/etc/init.d/smartdns-python disable`。若 `/opt` 在服务启动时尚未挂载，需要先解决挂载顺序。

启动后可运行 `ubus call service list '{"name":"smartdns-python","verbose":true}'` 检查 `main` 实例的 `jail`、`user`、`group`、`no_new_privs`、`capabilities` 和 `term_timeout` 参数；再用 `ps` 找到 Python 子进程 PID，检查 `/proc/PID/status` 中的 `Uid`、`Gid`、`NoNewPrivs`、`CapEff`、`CapPrm`、`CapInh`、`CapBnd` 和 `CapAmb`，以及 `/proc/PID/root` 是否指向 ujail 根目录。正常情况下 Python 进程的五个 capability 值均应为 `0000000000002400`（仅包含两项网络权限），`NoNewPrivs` 应为 `1`；若实际值不同，先检查 procd/ujail 版本及日志。若 procd 持续重启，先从 `logread -e smartdns` 和 `logread -e jail` 检查缺少的挂载或权限。

若已安装 `dig`，分别检查 UDP/TCP：

```sh
dig @127.0.0.1 -p 5335 example.org A
dig +tcp @127.0.0.1 -p 5335 example.org A
```

没有 `dig` 时，可用已经安装的 dnspython 检查：

```sh
/opt/smartdns-python/.venv/bin/python - <<'PY'
import dns.message
import dns.query
import dns.rcode

request = dns.message.make_query('example.org', 'A')
for protocol, query in (('UDP', dns.query.udp), ('TCP', dns.query.tcp)):
    response = query(request, '127.0.0.1', port=5335, timeout=5)
    print(protocol, dns.rcode.to_text(response.rcode()), response.answer)
PY
```

确认 UDP/TCP 查询成功后，用 `/etc/init.d/smartdns-python enable` 设置开机自启。

## 5. 可选：让 dnsmasq 转发到 SmartDNS

只在上一步查询成功后操作。OpenWrt 通常让 dnsmasq 继续监听 53 端口、为 LAN 提供 DHCP/DNS；SmartDNS 保持在本机 5335。先确认 SmartDNS 的上游不会再指回路由器的 dnsmasq，以免形成转发环。以下示例会替换 dnsmasq 当前的上游列表，请先查看现有的 `server`、`noresolv` 设置并备份：

```sh
uci show 'dhcp.@dnsmasq[0]'
cp /etc/config/dhcp /root/dhcp.before-smartdns-python
uci -q delete 'dhcp.@dnsmasq[0].server'
uci add_list 'dhcp.@dnsmasq[0].server=127.0.0.1#5335'
uci set 'dhcp.@dnsmasq[0].noresolv=1'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

检查路由器的 53 端口解析是否仍正常。若需恢复先前设置，执行 `cp /root/dhcp.before-smartdns-python /etc/config/dhcp && /etc/init.d/dnsmasq restart`。此示例不更改 LAN 客户端的 DHCP DNS 通告，也不让 SmartDNS 直接监听 LAN 地址。
