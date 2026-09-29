# OpenWrt 手动安装（procd）

此示例使用独立的 [`deploy/smartdns.openwrt.init`](../deploy/smartdns.openwrt.init)，按 [OpenWrt 的 procd 约定](https://openwrt.org/docs/guide-developer/procd-init-scripts)管理进程。它与 Debian/Ubuntu 的 [`deploy/smartdns.init`](../deploy/smartdns.init) 不通用，也不使用 [`deploy/install.sh`](../deploy/install.sh)。[OpenWrt 软件源中的另一款 `smartdns` 包](https://github.com/openwrt/packages/blob/master/net/smartdns/Makefile)会使用 `/etc/init.d/smartdns` 和 `/etc/smartdns`；本示例将 Python 服务命名为 `smartdns-python`，程序及配置都放在 `/opt/smartdns-python`，避免覆盖它。下列命令假定首次安装、以路由器的 root 用户操作。已有同名文件或目录时，请先检查和备份。

## 1. 确认设备能运行本项目

本项目要求 **Python 3.14 或更新版本**，还依赖 `aiofastnet`、`curl-cffi`、`marisa-trie`、`py-radix` 等原生扩展。先确认路由器的 CPU 架构、OpenWrt 的 musl ABI、可用存储空间，以及可运行的 uv 和对应依赖；普通 Linux 或 Windows 上创建的 `.venv` 不能直接复制到 OpenWrt。若目标平台缺少兼容的解释器、wheel 或编译环境，下面的服务脚本无法弥补这个问题。建议将 `/opt` 放在容量充足、开机时已挂载的持久存储上。

在路由器上检查：

```sh
uname -m
df -h / /tmp
uv --version
```

上述命令必须成功；`uv` 的取得方式取决于设备架构和固件软件源。第 3 步会在程序目录内安装 Python 3.14，服务启动时不会下载 Python 或依赖。若使用 DNSCrypt，上游还要求目标系统中有可动态加载的 libsodium。

此服务要求 OpenWrt 的 `procd-ujail`：在 25.12 及更新版本使用 `apk add procd-ujail`，在 24.10 及更早版本使用 `opkg update && opkg install procd-ujail`。确认 `test -x /sbin/ujail` 成功；启动脚本使用 `ls -ldn` 检查安全文件的数字 UID/GID 和权限，无需额外安装 `stat`。若设备内核或容器环境不允许创建 jail 所需的挂载命名空间，服务会启动失败，应先解决平台限制。

## 2. 建立专用用户并复制文件

OpenWrt 需要 `groupadd`、`useradd` 命令来创建本示例使用的 `smartdnspy` 用户。若未安装，OpenWrt 25.12 及更新版本可用 `apk add shadow-useradd shadow-groupadd`；24.10 及更早版本可用 `opkg update && opkg install shadow-useradd shadow-groupadd`（见 [OpenWrt 软件包管理说明](https://openwrt.org/docs/guide-user/additional-software/managing_packages)）。先确认软件源与固件版本匹配。在路由器上执行：

```sh
groupadd -r smartdnspy
useradd -r -g smartdnspy -M -d /var/run/smartdns-python -s /bin/false smartdnspy
id smartdnspy
```

如果从源码仓库部署最小示例配置，可在仓库根目录（开发机）打包并传到路由器；将示例地址换成路由器地址。该最小包不含 Geo 数据。如果配置使用 `geodata`，应在开发机运行 `uv run --no-sync python deploy/package.py` 生成源码 ZIP，再按下文的 ZIP 步骤安装。这个 ZIP 包含 `tags/geosite.dat`、自定义标签文本、转换器和 MaxMind DB，但不包含其他设备生成的 `geosite.trie`、`geoip.radix`。

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

全新安装若使用 `deploy/package.py` 生成的 `smartdns-deploy-*-source.zip`，请跳过上面的 tar 打包和解包步骤。ZIP 内有一个 `smartdns-deploy-*` 顶层目录，必须将**该目录的内容**复制到 `/opt/smartdns-python`，不能把顶层目录本身放进去。在路由器的 `/tmp` 中只保留一个匹配的 ZIP，并确认已安装 `unzip` 后执行：

```sh
STAGE=$(mktemp -d /tmp/smartdns-zip.XXXXXX)
unzip /tmp/smartdns-deploy-*.zip -d "$STAGE"
mkdir -p /opt/smartdns-python
cp -R "$STAGE"/smartdns-deploy-*/. /opt/smartdns-python/
test -f /opt/smartdns-python/pyproject.toml
test -f /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
```

如果路由器没有 `unzip`，可在开发机解压后把顶层目录**里面的文件**传到 `/opt/smartdns-python`。不要把开发机上的 `.venv` 一并复制到路由器；下一步要在路由器上重新运行 `uv sync`。已有部署若只需修复启动和停止问题，仅更新 `deploy/smartdns.openwrt.init` 与 `smartdns/main.py`，并重新安装 init 脚本；不要用整个 ZIP 覆盖现有 `config.yaml`。如果已有部署需要重建 Geo 数据，只复制 ZIP 内 `tags/geosite.dat`、`tags/geosite/`、`tags/geoip/` 和 `utils/` 的转换器源码，保留路由器上已有的 MaxMind DB，并按第 3 步重新生成。

示例配置只在 `127.0.0.1:5335` 监听 UDP/TCP，示例上游为 `1.1.1.1:53`，不需要 53 端口权限。**该上游并非在所有网络都可达**；在路由器上先运行 `nslookup example.org 1.1.1.1`。若失败，应将 `/opt/smartdns-python/config.yaml` 的 `upstream-udp.address` 换成已验证可达的 DNS 地址（可参考 `ubus call network.interface.wan status` 的 `dns-server`），再启动服务。若计划让 dnsmasq 转发到 SmartDNS，不能把 SmartDNS 上游设为路由器自己的 `127.0.0.1:53`，否则会形成转发环。启动前还须确认 5335 未被其他服务占用。自定义配置若引用 `tags/output` 等相对路径，路径从 `/opt/smartdns-python` 解析。服务以普通用户运行，请确保该用户能读取这些文件。与 systemd 示例一样，capability 配置提供 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`，可用于绑定 53 端口及运行特权 ICMP 测速；改用 53 端口前须先解除与 dnsmasq 等服务的端口冲突。

## 3. 在目标平台安装并检查依赖

在路由器上把 uv 管理的 Python 安装到程序目录，然后用它同步锁定依赖。**已有部署若让 dnsmasq 转发到本服务，必须先按第 5 节撤销该转发并确认 DNS 恢复，再停止服务和重建环境**；否则服务停止后客户端 DNS 会超时，uv 下载 Python 也可能失败。下面的命令会把指向程序目录外的旧 `.venv` 改名备份，并保留现有 `config.yaml`。若备份目录已存在，命令会停止，请先检查它。`--no-python-downloads` 避免同步依赖时意外下载另一份解释器；如果原生扩展在该平台无法安装，请先解决目标平台的构建/分发问题，再继续部署。

```sh
cd /opt/smartdns-python
UV_CACHE_DIR=/opt/smartdns-python/.uv-cache \
UV_PYTHON_INSTALL_DIR=/opt/smartdns-python/.python uv python install 3.14
PYTHON_PATH=$(UV_PYTHON_INSTALL_DIR=/opt/smartdns-python/.python \
    uv python find --directory /tmp --managed-python --no-python-downloads 3.14)
case "$(readlink -f "$PYTHON_PATH")" in
    /opt/smartdns-python/*) ;;
    *) echo "Python is outside /opt/smartdns-python" >&2; exit 1 ;;
esac
if [ -d .venv ]; then
    case "$(readlink -f .venv/bin/python)" in
        /opt/smartdns-python/*) ;;
        *)
            test ! -e .venv.before-local-python || {
                echo 'Existing .venv backup needs attention' >&2; exit 1;
            }
            mv .venv .venv.before-local-python
            ;;
    esac
fi
UV_CACHE_DIR=/opt/smartdns-python/.uv-cache \
UV_PYTHON_INSTALL_DIR=/opt/smartdns-python/.python \
    uv sync --locked --no-dev --no-python-downloads --python "$PYTHON_PATH"
readlink -f /opt/smartdns-python/.venv/bin/python
/opt/smartdns-python/.venv/bin/python -c 'import smartdns.main; print("imports OK")'
if [ -f tags/geosite.dat ]; then
    test -f utils/convert.py || { echo 'Geo converter is missing' >&2; exit 1; }
    test -f utils/message_pool.py || { echo 'Geo protobuf support is missing' >&2; exit 1; }
    /opt/smartdns-python/.venv/bin/python -m utils.convert \
        --geodata-path tags/geosite.dat --tag-path tags --output-path tags/output
fi
chown -R root:root /opt/smartdns-python
chmod -R go-w /opt/smartdns-python
chmod 0755 /opt/smartdns-python
chmod -R a+rX /opt/smartdns-python/smartdns
chmod -R a+rX /opt/smartdns-python/.python /opt/smartdns-python/.venv
if [ -d /opt/smartdns-python/tags ]; then
    chmod -R a+rX /opt/smartdns-python/tags
fi
if [ ! -e /opt/smartdns-python/config.yaml ]; then
    cp /opt/smartdns-python/deploy/config.yaml /opt/smartdns-python/config.yaml
fi
chown root:smartdnspy /opt/smartdns-python/config.yaml
chmod 0640 /opt/smartdns-python/config.yaml
chown root:root /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
chmod 0644 /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
```

仅改变 `UV_PYTHON_INSTALL_DIR` 不会修复已有虚拟环境中的旧解释器链接；确认新服务运行正常后再处理 `.venv.before-local-python` 备份。参见 [uv 的 Python 安装目录说明](https://docs.astral.sh/uv/reference/storage/)。`geosite.trie` 和 `geoip.radix` 必须在目标设备的 Python 与原生依赖就绪后生成；旧 ZIP 或其他架构构建的这两个文件不能作为新设备的已验证缓存。`geoip.metadb` 和 `asn.mmdb` 作为 MaxMind DB 文件继续保留。若配置引用 Geo 数据但没有这些输入文件，先补齐输入再启动服务，不能依赖旧缓存。

启动前还应确认这些检查均成功：

```sh
test -x /opt/smartdns-python/.venv/bin/python
case "$(readlink -f /opt/smartdns-python/.venv/bin/python)" in
    /opt/smartdns-python/*) echo 'Python path OK' ;;
    *) echo 'Python must be inside /opt/smartdns-python' >&2; exit 1 ;;
esac
test -r /opt/smartdns-python/config.yaml
ls -ldn /opt/smartdns-python/deploy/smartdns.openwrt.capabilities.json
id -u smartdnspy
```

上面 `ls -ldn` 的首列应为 `-rw-r--r--`，第三、四列数字 UID/GID 应均为 `0`。若使用可选的 `environment` 文件，其首列应为 `-rw-------`，UID/GID 同样为 `0`。

解释器的真实路径必须在 `/opt/smartdns-python` 下，而且 `smartdnspy` 用户必须能读取它。服务用户还必须能穿过程序目录、读取 `smartdns/*.py` 和配置引用的地理数据；仅给 `.python`、`.venv` 加读取权限不足以运行源码。`chmod -R go-w` 只移除写权限，不会给原本是 0600 的文件补上读取权限；因此上面另对源码与地理数据执行 `chmod -R a+rX`，但保留 `config.yaml` 的 0640 和可选 `environment` 的 0600。程序目录、Python 安装、虚拟环境和 capability 配置应始终保持 root 拥有且不可由该用户修改。jail 会只读挂载整个程序目录、常见系统库目录、CA 证书及主机解析文件；不再单独挂载解释器文件，因为某些 ujail 构建在处理该 Python 文件时会崩溃。如果原生库放在其他目录，需要把对应目录加入 init 脚本的只读挂载列表。如果日志出现 `PermissionError: .../smartdns/main.py`，先按本节修复源码读取权限。如果导入仍失败，再检查缺失的 Python 包、原生库或 ABI 问题。

对已安装的实例，遇到上述 `main.py` 权限错误时可直接修复并重新启动，无需重建虚拟环境或覆盖现有配置。如果 dnsmasq 已只转发到 SmartDNS，先按第 5 节撤销转发、确认路由器 DNS 恢复，再执行下列停机命令：

```sh
/etc/init.d/smartdns-python stop
chown -R root:root /opt/smartdns-python/smartdns
chmod -R go-w,a+rX /opt/smartdns-python/smartdns
if [ -d /opt/smartdns-python/tags ]; then
    chmod -R a+rX /opt/smartdns-python/tags
fi
/etc/init.d/smartdns-python start
/etc/init.d/smartdns-python status
logread -e smartdns | tail -n 20
```

若 DNSCrypt 使用的 libsodium 不在动态库默认搜索路径，可另建 `/opt/smartdns-python/environment`，写入一行 `SMARTDNS_LIBSODIUM_PATH=/绝对路径/libsodium.so`，并执行 `chown root:root /opt/smartdns-python/environment && chmod 0600 /opt/smartdns-python/environment`。init 脚本只读取这个赋值，不执行文件内容；它会拒绝符号链接、非 root:root 0600 文件以及其他配置项，并将该库只读挂载进 jail。启用 DNSCrypt 前，先用相同路径验证 `SMARTDNS_LIBSODIUM_PATH=/绝对路径/libsodium.so /opt/smartdns-python/.venv/bin/python -c 'from smartdns.nameservers._sodium import require_libsodium; require_libsodium()'` 能成功执行。

## 4. 安装并启动 procd 服务

```sh
test ! -d /etc/init.d/smartdns-python
cp /opt/smartdns-python/deploy/smartdns.openwrt.init /etc/init.d/smartdns-python.new
chown root:root /etc/init.d/smartdns-python.new
chmod 0755 /etc/init.d/smartdns-python.new
mv -f /etc/init.d/smartdns-python.new /etc/init.d/smartdns-python
/etc/init.d/smartdns-python start
/etc/init.d/smartdns-python status
logread -e smartdns
```

上面的临时文件加 `mv` 会将旧脚本或符号链接替换为名为 `smartdns-python` 的普通文件；只用 `cp` 覆盖已有符号链接可能会改写其目标、保留链接。`rc.common` 使用链接目标的文件名作为 procd 服务名，目标名与 `smartdns-python` 不同时，状态和停止命令可能查错服务。可用 `ls -l /etc/init.d/smartdns-python` 检查。

启动脚本让 procd 通过 `ujail` 监管 Python 服务，异常退出后重启；标准输出和错误进入 OpenWrt 日志。隔离配置使用专用用户/组、`no_new_privs`，并将 capability 的五个集合均限制为 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`；不挂载 `/proc`、`/sys` 或 ubus。程序与配置只读，仅 `/var/run/smartdns-python` 对服务可写，并作为 `HOME` 和 `TMPDIR`。该目录在每次启动时创建为 `smartdnspy:smartdnspy`、0700；Python 进程采用与 systemd 示例相同的 `0027` umask。`term_timeout 35` 为被隔离的进程提供 35 秒停止宽限时间。ujail 的 PID 命名空间可能让 Python 成为 PID 1；Linux 不会向没有注册相应处理器的命名空间 PID 1 递送通常的终止信号。程序入口显式接收 `SIGTERM`，取消主服务并清理监听器和 Worker。`rc.common` 的默认 `stop` 只发出异步删除请求；本脚本在请求之后最多等待 75 秒，进程仍运行时返回错误，不再报告停止成功。若需访问程序目录之外的地理数据、证书或库，先按最小范围补充只读挂载。修改 `/opt/smartdns-python/config.yaml`、capability 配置或 `environment` 后用 `/etc/init.d/smartdns-python restart`，停用自启动用 `/etc/init.d/smartdns-python disable`。若 `/opt` 在服务启动时尚未挂载，需要先解决挂载顺序。

启动后可运行 `ubus call service list '{"name":"smartdns-python","verbose":true}'` 检查 `main` 实例的 `jail`、`user`、`group`、`no_new_privs`、`capabilities` 和 `term_timeout` 参数；再用 `ps` 找到 Python 子进程 PID，检查 `/proc/PID/status` 中的 `Uid`、`Gid`、`NoNewPrivs`、`CapEff`、`CapPrm`、`CapInh`、`CapBnd` 和 `CapAmb`，以及 `/proc/PID/root` 是否指向 ujail 根目录。正常情况下 Python 进程的五个 capability 值均应为 `0000000000002400`（仅包含两项网络权限），`NoNewPrivs` 应为 `1`；若实际值不同，先检查 procd/ujail 版本及日志。若 procd 持续重启，先从 `logread -e smartdns` 和 `logread -e jail` 检查缺少的挂载或权限。

若 `start` 返回 0 而 `status` 显示 `not running`，请查看上述 `ubus` 输出的 `exit_code`，并用 `logread -e ujail` 检查内核日志。`exit_code: 139` 且日志显示 `ujail` 段错误时，先用 `readlink -f /opt/smartdns-python/.venv/bin/python` 检查真实路径；如果指向 `/root/.local/share/uv/python`，按第 3 步重新建立程序目录内的 Python 和虚拟环境，并更新 init 脚本。不要只改变 `.venv/bin/python` 的链接目标，已有虚拟环境可能保留旧路径。

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

需要停机时，执行 `/etc/init.d/smartdns-python stop`，再用 `/etc/init.d/smartdns-python status` 和 `ubus call service list '{"name":"smartdns-python","verbose":true}'` 核对；已停机时应显示 `inactive` 和空对象。若仍在运行，请查看 `logread -e smartdns` 和 `logread -e jail`。旧版入口没有 `SIGTERM` 处理器时，即使更新了 init 脚本，首次停止也可能等到 ujail 的 35 秒宽限期结束；下次启动的新入口会主动响应信号。不要单独 `kill` Python：只要 procd 服务仍注册，`respawn` 就会将它拉起。`stop` 对已不存在的服务可能显示 `Command failed: Not found`，这时以状态和 procd 列表为准。

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

检查路由器的 53 端口解析是否仍正常。**停止 SmartDNS 不会撤销 dnsmasq 的转发配置**；如果 SmartDNS 停止或查询超时，而 dnsmasq 仍只转发到 `127.0.0.1#5335`，客户端的 DNS 查询也会超时。先撤销这条转发，再重启 dnsmasq：

```sh
uci -q del_list 'dhcp.@dnsmasq[0].server=127.0.0.1#5335'
uci -q delete 'dhcp.@dnsmasq[0].noresolv'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

这会重新允许 dnsmasq 使用 WAN 提供的 DNS，但不会恢复本节此前删除的自定义 `server` 列表。若 `/root/dhcp.before-smartdns-python` 是启用转发前的备份，且此后未修改过其他 DHCP/dnsmasq 设置，可执行 `cp /root/dhcp.before-smartdns-python /etc/config/dhcp && /etc/init.d/dnsmasq restart` 完整恢复。确认路由器的 53 端口恢复解析后，再执行 `/etc/init.d/smartdns-python stop`；若实例仍在 procd 中，可用 `ubus call service delete '{"name":"smartdns-python"}'` 移除并用 `ubus call service list '{"name":"smartdns-python","verbose":true}'` 核对。不要单独 `kill` Python 进程：`respawn` 会让 procd 再次启动它。此示例不更改 LAN 客户端的 DHCP DNS 通告，也不让 SmartDNS 直接监听 LAN 地址。
