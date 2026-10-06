# SmartDNS

一个基于标签路由的高性能异步 DNS 代理/分流服务器。它在前端监听标准 DNS（UDP/TCP），在后端把请求按**地理/服务标签**分流到不同的上游解析器，并对返回结果做**测速择优、IP 替换、ECH 注入、失败回退**等加工后再回给客户端。

> 完整的源码级架构和处理流程见 [`docs/architecture.md`](docs/architecture.md)，逐字段配置参考见 [`docs/configuration.md`](docs/configuration.md)，可加载示例见 [`example.yaml`](example.yaml)。

- 语言：Python ≥ 3.14，全异步（`anyio` + `uvloop`/`winuvloop`）
- 配置：单一 `config.yaml`（`pydantic-settings` 校验）
- DNS 协议栈：`dnspython` + `aiodns`（pycares）+ `curl-cffi`（DoH/ECH）
- 地理数据：MaxMind（GeoIP/ASN）+ 自构建 MARISA-Trie（GeoSite）+ py-radix（IPSet）

---

## 目录

- [整体架构](#整体架构)
- [请求处理流程](#请求处理流程)
- [核心概念](#核心概念)
- [配置参考](#配置参考)
- [上游类型](#上游类型)
- [解析器类型](#解析器类型)
- [动作类型](#动作类型)
- [路由与匹配](#路由与匹配)
- [标签与地理数据](#标签与地理数据)
- [离线工具（utils/）](#离线工具utils)
- [运行与部署](#运行与部署)

---

## 整体架构

```text
                       ┌──────────────────────────────────────────────┐
                       │                    Master                     │
                       │  ListenerManager  +  N 个 Worker（独立事件循环）│
                       │                +  全局 Answer 缓存             │
                       └───────────────┬──────────────────────────────┘
                                       │ dispatch(request)  随机选 worker
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
       UDP/TCP Listener           Worker 0  ── Router 表 ──► (命中即停)
       (anyio socket +             Worker 1
        dnspython 收发)             ...
                                         │
                          ┌──────────────┴──────────────┐
                          ▼                             ▼
                    before Actions                 Resolver（上游）
                  (static/log/...)          ┌───────┴────────────┐
                          │                 │                    │
                          ▼              AioDNS / Plain      Concurrent
                  ── 命中即返回 ──         (aiodns/dnspython)  (并发多上游)
                                                │
                                  candidate Actions（Concurrent）
                                      (replace/speedcheck)
                                                │
                                         after Actions
                                   (speedcheck/https/fallback)
                                                │
                                                ▼
                                            回写响应
```

### 分层职责

| 层 | 目录 | 职责 |
|---|---|---|
| **入口** | `smartdns/main.py` | Typer CLI，加载 `config.yaml`，启动 Master |
| **核心** | `smartdns/core/` | `Master`（监听器+worker 调度+缓存）、`Worker`（单请求处理链）；Answer 缓存统一为 `utils.cache_async.AnswerCache`（跨线程共享 + async 读写 + 同键合并） |
| **监听器** | `smartdns/listeners/` | 对外收发 DNS 报文（UDP/TCP），把 `dns.message` 包成 `Request` |
| **上游服务器** | `smartdns/nameservers/` | 对单个上游 DNS 服务器的底层查询（UDP/TCP/curl-DoH） |
| **解析器** | `smartdns/resolvers/` | 上层解析策略（直连 / dnspython / 并发择优），聚合多个上游服务器 |
| **动作** | `smartdns/actions/` | 在路由链路上对请求或应答做加工（静态应答、日志、替换、测速、ECH、回退） |
| **路由** | `smartdns/routing/` | 标签查询（GeoIP/GeoSite/IPSet）、规则匹配器、规则执行器 `Router` |
| **模型** | `smartdns/models/` | 全部 `pydantic` 配置与运行时数据类 |
| **工具** | `utils/` | 离线脚本：地理数据转换、CDN IP 段抓取、Google(GWS) IP 枚举 |

### 多线程/多事件循环模型

- `Master` 启动 `worker_count` 个 `Worker`，每个 Worker 跑在**独立的 `BlockingPortal`（独立事件循环 + uvloop）**里。
- `Master` 自己的事件循环只负责**监听器收包**和**随机分发**到 Worker；真正解析在 Worker 循环里完成。
- 跨循环调用通过 `asyncio.wrap_future(portal.start_task_soon(...))` 桥接。
- Worker 各自持有上游连接/会话；跨线程读取进程级 GeoManager。Master Answer 缓存按查询三元组、监听器和 ECS 隔离（不包含客户端地址），缓存读写及 Action 改写均采用 copy-on-write。

---

## 请求处理流程

1. **监听器** 收到一个 DNS 报文 → `Request.from_message()`，顺带查好请求方的 `IPInfo`（国家/ASN）和被查域名的 `NameInfo`（GeoSite 标签）。
2. **Master.dispatch()**：先查全局应答缓存（`cached()` + TLRUCache，按应答 TTL 过期并合并同键并发），命中直接回；否则随机选一个 Worker，把 `Request` 投递过去。
3. **Worker.handle()**：构造贯穿全流程的 `Context`，进入 `process()`。
4. **路由表顺序匹配**：`Worker._rules` 按 `config.yaml` 中 `routing` 的顺序逐条尝试 `Router.query()`。
   - **匹配**：`Router.match()` 按域名的 `domain_include / domain_exclude / query_types` 判断（fail-closed）。
   - **before 动作**：转发上游前执行（如 `static` 直接静态应答、`log` 记录）；任一动作置 `context.stop` 即终止。
   - **resolver 查询**：调用命中的上游解析器拿到 `Response`。
   - **候选动作**：ConcurrentResolver 的直接上游返回带 Answer 的 NOERROR 后执行 `on_resolver`（如 `replace` 改 IP、`speedcheck` 采样）。
   - **after 动作**：路由拿到最终成功应答后执行 `on_response`（如 `speedcheck` 择优、`https` 注 ECH、`fallback` 回退）。
   - **短路**：一旦某条路由产出最终应答（含 NXDOMAIN 等权威否定应答），后续路由不再执行。
5. **回写**：`Master` 把最终 `Message` 回给监听器，监听器发回客户端。

> Master 缓存键包含查询三元组、监听器和入站 ECS；客户端地址不入键，因为当前上游查询不转发客户端地址，避免按客户端拆键造成命中率损失。

---

## 核心概念

### `Request` / `Response` / `Context`（`models/context.py`）

- **`Request`**：进来时即附带的轻量对象，含原始 `dns.message`、查询名/类型/类、来源地址、以及预查的 `name_info` / `ip_info`。提供 `make_answer()` / `make_error()` 生成回包。
- **`Response`**：上游返回结果的归一化封装。`Response.from_answer()` 会把 CNAME 链、A/AAAA 列表、HTTPS 记录里的 ipv4hint/ipv6hint 全部展平成 `ip_list` / `ip_infos` / `name_list` / `name_infos`，方便后续按标签匹配。
- **`Context`**：一次请求在 Worker 内贯穿所有 hook 的可变状态。关键字段：
  - `response`：当前最终应答
  - `candidates: dict[upstream, Response]`：并发解析时收集的所有候选应答（供 after 动作二次挑选）
  - `ip_infos: dict[ip, IPInfo]`：跨上游累积的 IP 测速结果
  - `stop: bool`：置位即中断当前路由链
  - `ext: dict`：任意扩展位

### `IPInfo` / `NameInfo`（`models/geodata.py`）

运行时的地理标签载体，构造时即向 `GeoManager` 查询并填好国家标签集与 ASN。

### `GeoManager`（`routing/manager.py`）

进程级单例（`init_geo_manager` / `get_geo_manager`），聚合 `GeoIP`（MaxMind）、`GeoSite`（MARISA-Trie）、`IPSet`（py-radix）。`lookup_ip()` 合并 GeoIP 与 IPSet 的标签；`lookup_domain()` 查 GeoSite。

---

## 配置参考

顶层字段（`models/config.py`）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `worker_count` | int | Worker 数（默认 `cpu_count()`） |
| `cache_size` | int | Master 全局缓存容量，`0` 关闭 |
| `geodata` | object | geo 数据文件路径 |
| `client` | object | HTTP（curl）客户端共用配置 |
| `listeners` | list | 对外监听器 |
| `nameservers` | list | 底层上游服务器 |
| `resolvers` | list | 上层解析策略 |
| `actions` | list | 动作定义 |
| `routing` | list | 路由规则（顺序执行） |

可复制的 `example.yaml` 示例见仓库根目录；`config.yaml` 是当前开发配置。

---

## 上游类型

`nameservers/` —— 一个 `Nameserver` 表示**一台**上游 DNS 服务器，实现 dnspython 的 `Nameserver.async_query` 接口。

| `type` | 类 | 说明 |
|---|---|---|
| `udp` | `UDPNameserver` | UDP 直连。`repeat` 重复发包提高成功率；`use_tricks` 启用"多收几跳跳过伪造包"的接收技巧；截断响应自动对同一上游改用 TCP 重试 |
| `tcp` | `TCPNameserver` | TCP 直连。`pool_size>0` 时用 `generic_connection_pool` 复用连接；`use_tricks` 尝试非阻塞 OOB 前缀发送，不支持或失败时回退完整报文的普通异步发送 |
| `curl` | `CurlNameserver` | 用 `curl-cffi`（chrome 指纹）发 DoH。支持自定义 `Host`、GET/POST、证书校验开关、**ECH**（从指定域名现查 HTTPS 记录取 ECH 密钥） |

> curl 会话**每个上游独占一份** `AsyncSession`，避免共享会话被逐请求改 ECH 选项导致竞态。

所有上游用 `anyio` 的 socket 适配成 dnspython 后端 `DatagramSocket` / `StreamSocket`（`nameservers/_socket.py`、`listeners/_socket.py`），从而统一用 `dns.asyncquery` 的收发逻辑。

对客户端回包时，UDP 遵循 EDNS payload（无 EDNS 为 512 字节），大响应以 `TC=1` 截断；TCP 则返回最大 65535 字节的完整 DNS 消息。因此 `cloudflare.com` 这类较大的 TXT 响应不会再因 `TooBig` 被静默丢弃。

---

## 解析器类型

`resolvers/` —— `Resolver` 表示**一种解析策略**，聚合若干 `Nameserver` 或下层 `Resolver`。

| `type` | 类 | 说明 |
|---|---|---|
| `aiodns` | `AioDNSResolver` | 基于 `aiodns`/pycares 的异步解析，内置完整记录类型转换（A/AAAA/MX/TXT/CAA/CNAME/HTTPS/NAPTR/NS/PTR/SOA/SRV/TLSA/URI）；长 TXT 按 255 字节上限重新分段。把 pycares 的 `DNSResult` 重新组装成 `dns.resolver.Answer`。支持 EDNS、TCP 模式、tries、轮询；NODATA 空应答按 `nodata_ttl` 写入负缓存；`resolve()` 边界带 `AnswerCache` 应答缓存（`cache_size`，0 关闭） |
| `plain` | `PlainResolver` | 继承 `dnspython.Resolver`，把配置里的上游**名字**解析成 `Nameserver` 实例挂在 `resolver.nameservers` 上，由 dnspython 自行调度。支持固定 ECS（EDNS Client Subnet）和 `lifetime`；应答缓存为 `AnswerCache`（`cache_size` 容量，按应答自身 TTL 过期，相同完整配置跨 Worker 共享），不用 dnspython 的 Resolver.cache |
| `concurrent` | `ConcurrentResolver` | 按完成顺序消费结果；`wait_all=false` 在首个带 Answer 的 NOERROR 后取消其余查询，`wait_all=true` 在整体超时内收集候选供 after 动作挑选 |

---

## 动作类型

`actions/` —— `Action` 是路由链路上的处理单元，按调用时机分三种 hook（`base.py` 默认 no-op）：

| Hook | 时机 | 典型用途 |
|---|---|---|
| `on_request(context)` | 路由 `before` 阶段（转发上游前） | 静态应答、日志 |
| `on_resolver(context, response)` | resolver 拿到每个候选应答后（`concurrent` 的每上游、路由的 after 前） | IP 替换、测速采样 |
| `on_response(context)` | 路由 `after` 阶段（即将回客户端前） | 测速择优、ECH 注入、失败回退 |

| `type` | 类 | 阶段 | 说明 |
|---|---|---|---|
| `static` | `StaticAction` | before | 用配置的 `ipv4/ipv6` 直接生成应答并 `stop`，用于屏蔽（示例里配合 `ads` 路由实现广告拦截） |
| `log` | `LogAction` | before | 打印请求摘要 |
| `replace` | `ReplaceAction` | on_resolver | 命中 IP 标签的应答按映射改写 IP，**保留主机位**：用原 IP 在 `prefixlen` 外的主机位作偏移叠加到新基址上（用于把 CDN IP 重定向到自有优选 IP 段） |
| `speedcheck` | `SpeedcheckAction` | on_resolver + on_response | 优先选择有有效 RTT 的 IP，按 RTT × 倍率排序并在相同标签集合、加权 RTT 阈值内取前 N 个；所有候选都没有有效 RTT 时仅按倍率排序取前 N 个。倍率先查 `tag_multipliers`，再查 `asn_multipliers`，默认 1；关闭探测后仍可使用已有 RTT。应答发送时保留排序顺序 |
| `https` | `HTTPSAction` | on_response | 清理 ServiceMode 记录的 ipv4/ipv6 hint 和 ALPN 中的 h3，同步修正 mandatory/no-default-alpn 依赖；AliasMode 保留别名。为命中域名+IP 标签的记录注入 ECH 密钥 |
| `fallback` | `FallbackAction` | on_response | 若应答无 IP 或候选 IP 测速**全部失败**，则命中映射的域名回退到静态 IP 列表；未测速的 IP 仍视为可用候选 |

> ECH 缓存按来源 HTTPS 应答的剩余 TTL 到期（最长 300 秒），临时查询失败不缓存；注入或合成的 HTTPS 记录也受 ECH 来源期限限制。HTTPS 的 A 子查询经完整 A 路由，并复用 Master 最终应答缓存及同键在途查询，保留监听器、客户端、ECS 和请求预算；内部子查询只执行一层。此处复用的是已完成加工的 A 应答，监听器发送仍由各客户端请求独立完成。

> 测速结果缓存 1800 秒，并按 IP、协议方式、ICMP 特权模式、端口和超时配置区分；同一事件循环内合并进行中的同键测速。测速和容量排队共同受测速预算限制，耗尽后保留未测得 RTT 的候选并继续过滤。外部取消不会发布未完成的候选。

> 单个 Nameserver 的 `timeout` 是上限，与调用方剩余预算取较小值。DoH 校验 Question、QR、opcode 和完整性，并扣除 HTTP Age；DNS ID 通过 HTTP 请求关联，允许与请求不同。DNS 缓存保持 CNAME 链最短期限，TTL=0 不进入持久缓存；静态 NODATA 按配置 TTL 到期。

---

## 路由与匹配

### `Rule`（`models/rule.py`）

```yaml
- name: rule1
  matcher:          # 请求匹配器（可选，缺省=匹配全部）
    domain_include: [cn]       # 域名须命中这些 GeoSite 标签之一
    domain_exclude: [...]      # 命中这些标签则不匹配
    query_types: [A, AAAA]     # 限定查询类型
  resolver: cn      # 命中后用哪个解析器
  before: [log]     # 转发前动作
  after: [speedcheck, https]  # 转发后动作
```

### `Router`（`routing/router.py`）

每条规则封装成一个 `Router`，`query()` 执行：

```
match()? → before actions → resolver.query() → after actions → 返回是否产出最终应答
```

短路规则（见 `router.py` 注释）：
- 不匹配 → 交后续路由。
- before 阶段 `stop` → 本路由产出，停。
- 无 resolver 或未产出应答 → 交后续路由（避免黑洞）。
- 应答为 NXDOMAIN 等权威否定 → 作为最终结果，**跳过 after**。
- after 阶段 `stop` → 本路由产出，停。

### `matcher`（`routing/matcher.py`）

统一的匹配原语层（见 `docs/superpowers/specs/2026-08-07-unified-matching-design.md` 的设计意图）：

- `match_request()`：请求级（query type 大小写归一、domain include/exclude），**include fail-closed**（配置了 include 但无 geo 标签则不匹配）、exclude 仅在有标签时判断。
- `match_response()` / `filter_ip()`：响应级，按 IP 标签与 ASN 判断；响应 include 用 OR（IP 或 ASN 任一命中），exclude 全局优先（任一项命中则整体失败）。
- `match_context()`：同时看请求域名和响应 CNAME 链的标签。
- `match_response_cname()`：CNAME 链标签匹配。

### 调用点

- `Router.match()` 负责解析前的请求匹配。
- `Replace / HTTPS / Fallback` 在拿到应答后调用响应匹配原语，各自取所需粒度（Replace 要具体 IP，Fallback 要过滤后的 IP 列表，HTTPS 只要布尔）。

---

## 标签与地理数据

匹配器里的 `domain_include` / `ip_include` / `asn_include` 等填的都是**标签**（如 `cn`、`cloudflare`、`google`、`category-ads`），不是字面域名/IP。标签由三份数据提供：

| 数据 | 文件 | 来源 | 运行时加载类 |
|---|---|---|---|
| GeoIP | `geoip.metadb` | MaxMind mmdb（自定义形状：record 直接是标签 str/list） | `routing/geoip.py` |
| ASN | `asn.mmdb` | MaxMind ASN 库 | 同上 |
| GeoSite | `geosite.trie` | MARISA-Trie（逆序点分标签建键） | `routing/geosite.py` |
| IPSet | 可选 `.radix`（pickle） | py-radix | `routing/ipset.py` |

标签查询会把一个 IP/域名映射到**一组**标签（如 `1.1.1.1` → `{cloudflare, us}`），匹配即集合相交判断。
`geosite.trie` 和 `geoip.radix` 是由本机原生扩展生成的运行时数据；跨架构部署时，安装目标平台的 Python 依赖后，应从 `tags/geosite.dat`、`tags/geosite/*.txt`、`tags/geoip/*.txt` 重新生成。`geoip.metadb`、`asn.mmdb` 是独立的 MaxMind DB 数据文件，不需要用 `utils.convert` 重建。进程内 DNS 应答缓存不会写入部署包。

---

## 离线工具（utils/）

| 脚本 | 作用 |
|---|---|
| `convert.py` | 把 mihomo 的 `geosite.dat`（protobuf）+ `tags/geosite/*.txt` + `tags/geoip/*.txt` 离线编译成运行时只读的 `geosite.trie` 与 `geoip.radix` |
| `fetch_ip.py` | 从各 CDN 官方 API（Cloudflare/CloudFront/Fastly/Google）抓取 IP 段，剔除中国段，切分成 /24 或 /48、/22、/48 网段写入 `cloudflare.txt` 等，供 `replace`/`fallback` 使用 |
| `gws.py` | Google GWS（Google Web Server）IP 枚举：反向解析 `1e100.net` PTR，按 `<dcid>-in-f<offset>` / `-in-x<hex>` 规则还原数据中心基础 IP，输出 JSON |

---

## 运行与部署

### 安装

```bash
uv sync
```

### 启动

```bash
uv run python main.py --config example.yaml
# 或
uv run python -m smartdns.main --config example.yaml
```

当前 `pyproject.toml` 未声明 `smartdns` 控制台脚本，Typer 也以单命令模式运行，因此不要附加 `start` 子命令。

### Linux 服务安装示例

仓库的 [`deploy/install.sh`](deploy/install.sh) 提供首次安装示例，支持 systemd 和 Debian/Ubuntu 的 SysV `init.d`（使用 `start-stop-daemon`）。先准备系统可访问的 Python 3.14 和 [`uv`](https://docs.astral.sh/uv/getting-started/installation/)；如果配置了 DNSCrypt 上游，还须安装可动态加载的 libsodium。脚本不会安装这些系统依赖，也不会自动启动服务。

如果希望逐条执行安装命令，请参阅 [`docs/manual-installation.md`](docs/manual-installation.md)。

```bash
# 从仓库根目录运行；省略第二个参数时使用 deploy/config.yaml
sudo sh deploy/install.sh systemd
# 或在使用 SysV init 的 Debian/Ubuntu 系统上：
sudo sh deploy/install.sh initd /path/to/your-config.yaml
# 自定义 libsodium 库路径时，第三个参数传入只含 KEY=value 的环境文件：
sudo sh deploy/install.sh systemd /path/to/your-config.yaml /path/to/environment
```

安装脚本将运行代码和 `config.yaml` 都放在 `/opt/smartdns`。systemd 模式要求版本不低于 247，使用 `DynamicUser=yes`，无需创建固定用户；SysV 模式仍会创建无登录权限的 `smartdns` 用户。已有应用目录或服务文件会使脚本停止，避免覆盖现有部署。若源码目录含 `tags/geosite.dat`，脚本会复制 Geo 输入并在目标设备安装完依赖后生成 `geosite.trie`、`geoip.radix`；`tags/output` 中仅复制 MaxMind DB 文件，不复制其他设备的构建产物。配置中的相对地理数据路径以 `/opt/smartdns` 为起点。安装时会校验配置及可选的 libsodium 加载。

默认的 [`deploy/config.yaml`](deploy/config.yaml) 只监听 `127.0.0.1:5335` 的 UDP/TCP，并转发到 `1.1.1.1:53`。要对外提供 DNS 服务，请先检查监听地址、端口、上游和主机防火墙，再启动服务。完整功能配置可参考 [`example.yaml`](example.yaml)，其中的占位地址需要按实际环境调整。

```bash
# systemd：先检查 /opt/smartdns/config.yaml，然后启用并启动
sudo systemctl enable --now smartdns
systemctl status smartdns
journalctl -u smartdns -f

# SysV init：在对应系统上安装开机链接并启动
sudo update-rc.d smartdns defaults
sudo service smartdns start
sudo service smartdns status
sudo tail -f /var/log/smartdns.log
```

systemd 示例用 `LoadCredential=` 将程序目录中 root 私有的配置交给动态用户读取，并授予绑定低端口所需的 `CAP_NET_BIND_SERVICE` 和 `icmplib` 原始 ICMP 测速所需的 `CAP_NET_RAW`。`init.d` 示例以固定普通用户运行，因此监听端口须不低于 1024；默认的 5335 可直接使用。它依靠专用用户和 Python 可执行文件识别进程，并使用 `/var/log/smartdns.log` 记录输出；长期运行时请为该日志配置轮转。若 DNSCrypt 所需的 libsodium 不在系统默认搜索路径，请将仅由 root 修改的环境文件作为安装脚本的第三个参数传入，其中写一行 `SMARTDNS_LIBSODIUM_PATH=/绝对路径/libsodium.so`。脚本会把它复制到 `/opt/smartdns/environment`，供两种服务配置读取。更改配置后重启服务即可生效。

### OpenWrt（procd）

OpenWrt 请使用独立的 [`deploy/smartdns.openwrt.init`](deploy/smartdns.openwrt.init) 和[手动安装说明](docs/openwrt-installation.md)。该示例把本 Python 项目注册为 `smartdns-python`，避免覆盖 OpenWrt 软件源中另一款同名 `smartdns` 的服务和配置。运行前需先在目标平台解决 Python 3.14、uv 和原生扩展的兼容性；本仓库的 Debian/Ubuntu `init.d` 脚本不适用于 OpenWrt。

### 准备地理数据

```bash
# 1. 放置 geosite.dat 到 tags/
# 2. 编译
uv run python -m utils.convert --geodata-path tags/geosite.dat --tag-path tags --output-path tags/output
# 3. （可选）抓取 CDN 优选 IP 段
uv run python -m utils.fetch_ip --output-path utils
# 4. （可选）GWS IP 枚举
uv run python -m utils.gws --domain domains.txt --ip ips.txt --output output.json
```

### 质量检查

修改代码后依次执行格式检查、静态分析、类型检查和测试：

```bash
uv run ruff format --check <修改的 Python 文件>
uv run ruff check .
uv run ty check
uv run pytest
```

当前手写代码、测试和工具均纳入 Ruff、Ty 与 Pytest 门禁；mihomo protobuf 生成代码在工具配置中排除。

### 配置要点

- 即使 `worker_count: 1`，Master 与 Worker 也运行在不同事件循环；增大数量会增加 Worker 线程并复制上游连接/会话。
- 想关缓存：`cache_size: 0`。
- 广告拦截：定义 `static` 动作（默认 127.0.0.1 / ::1）+ 一条 `domain_include: [category-ads-all]` 的路由放在最前。
- CDN 优选：用 `replace`（改写到自有优选段，保留主机位）或 `speedcheck`（实测择优）。
- 防 DNS 污染：UDP 上游可开 `use_tricks` 多收并过滤明显异常包；TCP 可开 `use_tricks` 尝试 OOB 前缀发送，失败时自动回退普通异步发送。
- ECH：`curl` 上游 + `https` 动作配合，可对 Cloudflare 等 CDN 的 HTTPS 记录注入 ECH 密钥。
