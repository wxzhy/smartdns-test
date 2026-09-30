# SmartDNS 项目实现说明

本文档依据当前工作区源码整理，重点描述已经接入运行链路的功能、请求处理流程、主要对象关系、配置语义和已知边界。仓库根目录的 `config.yaml` 更接近开发者本机配置；可复制使用的参考配置见 `example.yaml`。

## 1. 项目定位

SmartDNS 是一个以标签路由为核心的异步 DNS 代理。它接收客户端的 UDP/TCP DNS 请求，根据域名标签和查询类型选择解析器，再按需对响应执行测速、IP 替换、HTTPS/SVCB 参数调整、ECH 注入或失败回退。

当前技术栈：

- Python 3.14，项目的 `.python-version` 使用 free-threaded 构建。
- AnyIO 负责套接字、任务组和 Worker 事件循环；`aiofastnet.patch_loop()` 与 `use_uvloop` 用于事件循环优化。
- dnspython 负责 DNS 报文、Resolver 和上游接口。
- aiodns/pycares 提供直连 DNS 解析器。
- curl-cffi 提供 DoH、浏览器指纹和 ECH 相关能力。
- utls（BoringSSL）提供 DNS-over-TLS 握手与 ClientHello 指纹伪装。
- Pydantic Settings 负责 YAML 配置加载与字段校验。
- MaxMind、MARISA-Trie 和 py-radix 提供 IP、ASN、域名及自定义网段标签查询。

## 2. 目录与主要结构

```text
smartdns/
├── main.py                 CLI、配置加载、Master 启动
├── core/
│   ├── master.py           监听器、全局缓存、Worker 调度与停机
│   └── worker.py           单请求路由处理链与组件生命周期
├── listeners/              面向客户端的 UDP/TCP DNS 监听
├── nameservers/            单个底层上游：UDP、TCP、TLS、DNSCrypt、curl DoH
├── resolvers/              解析策略：aiodns、plain、concurrent
├── routing/                路由、匹配与 Geo 数据查询
├── actions/                请求前及响应后的加工动作
├── models/                 Pydantic 配置模型和运行时上下文
└── utils/cache_async.py    异步结果缓存与同键请求合并

utils/
├── convert.py              GeoSite/IPSet 离线转换
├── fetch_ip.py             CDN/Google IP 数据抓取脚本
└── gws.py                  Google GWS 地址枚举工具

tests/                      导入、路由、解析器、上游和生命周期测试
```

各层通过名称引用连接：

```text
routing[].resolver ───────────────► resolvers[].name
routing[].before / after ─────────► actions[].name
concurrent.resolvers ─────────────► 之前已声明的 resolvers[].name
concurrent.actions ───────────────► actions[].name
plain.nameservers ────────────────► nameservers[].name
```

`aiodns.nameservers` 是例外：其中填写 IP 地址字符串，不引用 `nameservers` 节点。

## 3. 启动和生命周期

### 3.1 CLI 与配置加载

根入口 `main.py` 只导入 `smartdns.main.app`。当前 Typer 应用只有一个命令，因此它以单命令模式运行，实际启动方式是：

```bash
uv sync
uv run python main.py --config example.yaml
# 等价写法
uv run python -m smartdns.main --config example.yaml
```

当前 `pyproject.toml` 没有声明 `[project.scripts]`，所以没有可直接调用的 `smartdns` 控制台命令；CLI 也不接受额外的 `start` 子命令。

配置来源按优先级为：构造参数、YAML、环境变量。顶层及嵌套未知字段都会报错；重复名称、Nameserver/Resolver/Action 引用、Resolver 声明顺序和未实现的 Listener 类型也在加载阶段校验。配置文件引用的本地 Geo 文件使用 `FilePath` 校验，启用时必须在加载配置前存在。

### 3.2 Master 和 Worker

`Master.start()` 执行以下步骤：

1. 修补当前事件循环并初始化全局 GeoManager。
2. 创建测速相关缓存对象。
3. 按 `worker_count` 创建 Worker；每个 Worker 都运行在独立的 `BlockingPortal` 和事件循环线程中。
4. 等待每个 Worker 完成 HTTPClient、Nameserver、Action、Resolver 和 Router 初始化。
5. 在 Master 所在事件循环启动所有 UDP/TCP 监听器。

这里的 `worker_count` 是 Worker 线程/事件循环数量，不是操作系统进程数。每个 Worker 都会单独创建上游对象、TCP 连接池和 curl 会话；增大数量会提高并行度，也会按 Worker 数复制这些资源。

停机时，Master 先关闭监听器，再让各 Worker 按 Resolver、Nameserver、Action、HTTPClient 的顺序释放资源，最后退出各 BlockingPortal。

## 4. DNS 请求处理流程

```text
客户端
  │ UDP/TCP DNS 报文
  ▼
Listener
  │ Request.from_message()
  │ 预查请求域名标签、客户端 IP 标签/ASN
  ▼
Master.dispatch()
  ├─ 全局缓存命中 ───────────────────────────────► 回包
  └─ 未命中：随机选择一个 Worker
                    │
                    ▼
               Worker.handle()
                    │ 创建 Context
                    ▼
          按 routing 顺序遍历 Router
                    │
          match → before → resolver → after
                    │
                    ▼
           Response / SERVFAIL
                    │
          Master 写缓存并重建客户端响应
                    ▼
                  回包
```

### 4.1 Listener

- UDP Listener 逐包接收 DNS 消息，每个包独立调用处理器。
- TCP Listener 接受长连接，并在同一连接内循环处理多个 DNS 消息。
- 两者都使用 dnspython 的 `receive_*`/`send_*`，底层通过 AnyIO socket 适配器接入。
- UDP 响应按客户端 EDNS payload 序列化；无 EDNS 时使用传统 512 字节上限。超限时返回 `TC=1` 的截断响应，由客户端改用 TCP 重试，而不是丢包超时。
- UDP 请求处理保持并发，但共享 Listener socket 的 datagram 写入会在适配器内排队，避免 AnyIO 对并发写入抛出 `BusyResourceError`。
- TCP 响应按 DNS over TCP 的 65535 字节上限完整序列化，不继承查询中的 UDP EDNS payload 限制。
- `Request.from_message()` 使用第一条 Question，填充 `qname`、`rdtype`、`rdclass`、客户端地址、`NameInfo` 和 `IPInfo`。
- 单包或单连接处理异常只记录日志；Master/Worker 内部异常统一降级为 SERVFAIL。

运行时 ListenerManager 目前只创建 UDP 和 TCP Listener。HTTP/DoH Listener 尚未实现，`type: http` 会在配置加载阶段被明确拒绝。

### 4.2 Master 缓存与调度

Master 的应答缓存经 `cached()` 装饰 `_query_answer()` 实现：持久层是 `cachetools.TLRUCache`（ttu 取 `Answer.expiration`，即应答自身 TTL），读取、写入与同键 in-flight 合并由装饰器统一处理。缓存键是：

```text
(qname, rdtype, rdclass, listener, ecs)
```

命中时会按剩余有效期刷新 answer、authority 和 additional 中 RRset 的 TTL（复制回放，缓存内原件不外泄），然后基于原始请求构造响应。未命中时使用随机策略选择一个 Worker；dispatch 仅运行于 Master 主循环，同缓存键并发请求会合并为一次 Worker 查询，等待者再用各自的 DNS 请求 ID 构造响应。

Worker 返回带 `Answer` 的 NOERROR 或 NXDOMAIN 时，Master 会原样透传并写缓存；NXDOMAIN 的 authority 区 SOA 与负缓存 TTL 因而得以保留。没有 `Answer` 的错误响应（含 SERVFAIL/REFUSED 等瞬态失败）经异常通道回传、只按 RCODE 构造，不进缓存。NXDOMAIN 仅记 debug，SERVFAIL/REFUSED 记 warning。

### 4.3 Worker 与 Router

Worker 为每个请求创建 `Context`，再按 `routing` 的配置顺序调用 Router。单条 Router 的执行次序为：

```text
match(request)
  └─► before actions
        └─► resolver.query()
              └─► after actions
                    └─► 子查询（on_response 设置了 subquery 时）→ on_subquery
```

关键短路规则：

- 规则不匹配：继续下一条规则。
- before 动作设置 `context.stop`：立即结束路由链。
- 规则未配置有效 Resolver，或 Resolver 没有生成 Response：继续下一条规则。
- Resolver 返回 NXDOMAIN、SERVFAIL 等非 NOERROR：把它作为最终结果，并跳过 after 动作。
- NOERROR 响应执行完 after 动作后结束路由链。
- 所有规则均未产出结果：Worker 返回 SERVFAIL。

因此，最后通常要放一条不带 `matcher` 的兜底路由。

## 5. 核心运行时对象

### Request

`Request` 保存原始 DNS Message、第一条 Question、监听器名称、客户端地址和预计算标签信息，并负责基于上游 Answer/RCODE 构造客户端响应。

### Response

`Response` 统一包装解析器输出：

- `rcode`：响应码。
- `ans`：dnspython `Answer`。
- `upstream`：实际产出响应的 Resolver 名称。
- `ip_infos`：A、AAAA 或 HTTPS hint 中解析出的 IP、标签、ASN、RTT 和来源 Resolver。
- `name_infos`：CNAME 链目标的标签信息。
- `invalid`：供 Action 标记候选无效的扩展位；FilterAction 会在 on_resolver 阶段设置它，被标记的候选不参与竞速选择和候选收集。

### Context

`Context` 贯穿一次 Worker 处理过程：

- `response`：当前最终响应。
- `candidates`：ConcurrentResolver 收集的候选响应，按 upstream 名称索引。
- `ip_infos`：跨候选聚合的测速信息。
- `stop`：动作触发的路由短路标志。
- `is_subquery`：内部查询标记；ConcurrentResolver 打在其嵌套解析器的子上下文上。
- `subquery`：on_response 阶段由 Action 设置的子查询上下文；Router 在 after 动作之后以当前 resolver 执行它，并回调 on_subquery。
- `ext`：扩展数据槽。

## 6. Nameserver：底层单上游

Nameserver 代表 dnspython 可调用的一台底层上游，只被 `plain` Resolver 通过名称引用。

| 类型 | 实现 | 主要行为 |
|---|---|---|
| `udp` | `UDPNameserver` | 每次查询创建 connected UDP socket；`repeat` 控制重复发包次数；`use_tricks` 最多多收几次并按报文特征过滤明显异常包；上游返回 `TC=1` 时由 dnspython 触发对同一地址的 TCP 重试 |
| `tcp` | `TCPNameserver` | 普通 DNS over TCP；`pool_size > 0` 时使用连接池复用连接；`use_tricks` 尝试非阻塞 OOB 前缀发送，失败时回退完整报文的普通异步发送 |
| `tls` | `TLSNameserver` | DNS over TLS：utls/BoringSSL 握手，`fingerprint` 指定 ClientHello 伪装预设（缺省 `chrome:stable`，null 为标准握手）；`pool_size > 0` 时用连接池复用握手完成的加密连接，健康检查沿用底层 TCP socket 的 `MSG_PEEK`；分帧与 DNS over TCP 相同，复用 `dns.asyncquery.tcp` |
| `dnscrypt` | `DNSCryptNameserver` | DNSCrypt 协议 2（X25519 + XChaCha20_DJB-Poly1305，PyNaCl 密钥/证书 + libsodium crypto_box），`dnsstamps` 解析 `sdns://` stamp；启动时经上游自身端点的明文 TXT 查询取证书并选 serial 最高的 es2 证书，临期自动刷新；UDP 应答 TC 由 dnspython 以 `max_size=True` 重调改走 TCP，每条 TCP 连接只处理一个查询；应答校验 nonce、填充、DNS ID 与问题 |
| `curl` | `CurlNameserver` | 使用独占的 curl-cffi AsyncSession 发送 DoH GET/POST；可改 Host、证书验证并请求 ECH 配置；`fingerprint` 指定 curl-cffi 指纹模拟目标（缺省 chrome，null 不模拟），未知值在配置加载期拒绝 |

curl 会话由各 CurlNameserver 独占，避免不同 DoH 上游共享并修改同一个 ECH 会话配置。`client.hosts` 会转换为 curl `RESOLVE`，仅为这些 HTTP 请求提供静态主机映射。

TCP pool 使用非破坏性的 `MSG_PEEK` 健康检查，不会关闭被检查的底层 socket；查询失败的连接由连接池按异常路径回收。

TLS 上游的握手与加密流由 `smartdns.nameservers._tls` 自行驱动：anyio 的 `TLSStream` 会把 hostname 经 IDNA 编码成 bytes 传给 `wrap_bio`，而 utls 只接受 `str`，因此不能用 `TLSStream` 直接包装。`server_name` 是 SNI 与证书验证锚点——域名地址默认取地址本身，IP 地址不发送 SNI（RFC 6066）；`verify: true` 且无法确定锚点时启动报错。`fingerprint` 接受 utls 预设名（如 `chrome:stable`）伪装 ClientHello。池内连接 `aclose` 不做 close_notify，省一次关闭往返。

`curl.ech` 的语义为：字符串值通过 `client.resolver` 查询指定域名的 HTTPS 记录并提取 ECHConfig；`true` 启用 curl 自动 ECH；`false` 不为该 Nameserver 设置 ECH 选项。

## 7. Resolver：解析策略

### 7.1 AioDNSResolver

`type: aiodns` 直接把 `nameservers` 中的 IP 地址交给 pycares，不经过 `nameservers` 管理器。它支持 EDNS、轮询、TCP、端口和重试次数，并把 pycares 结果转换为 dnspython Answer。

已转换的记录类型包括 A、AAAA、CAA、CNAME、HTTPS、MX、NAPTR、NS、PTR、SOA、SRV、TLSA、TXT 和 URI。pycares 会丢失 TXT 的原始 character-string 分段边界，因此长 TXT 会按每段最多 255 字节重新分段后编码。ARES_ENODATA 映射为空 NOERROR，ARES_ENOTFOUND 映射为 NXDOMAIN，其他异常映射为 SERVFAIL。

应答缓存经 `AnswerCache` 挂在 `resolve()` 边界（`cache_size` 默认 10000，`0` 关闭）：`query()` 路径与 HTTPClient 的 ECH 引导查询共用同一份按完整解析器配置共享的缓存，条目按应答自身 TTL 过期（NODATA 为 `nodata_ttl`），同事件循环内同键并发合并为一次 pycares 查询。同名但配置不同的解析器使用不同缓存。

### 7.2 PlainResolver

`type: plain` 继承 dnspython 异步 Resolver，并把配置里的 Nameserver 名称解析成自定义 UDP/TCP/curl 对象。它支持轮询、EDNS、固定 ECS、单次尝试 `timeout` 和查询总时限 `lifetime`。

`BaseResolver` 写入的 `timeout` 会覆盖 dnspython Resolver 的同名属性，作为单次上游尝试时限；`query()` 还显式传入 `lifetime` 作为整个解析过程的总时限。

应答缓存不走 dnspython 的 Resolver.cache，而是经 `cached()` 装饰 `_resolve_answer()` 实现：持久层按完整解析器配置注册并跨 Worker 线程共享（同名但配置不同的解析器相互隔离），底层使用 `cachetools.TLRUCache`（ttu 取 `Answer.expiration`，负应答即 SOA TTL）。同一事件循环内的同键并发由装饰器的 in-flight 表合并为一次上游查询；携带 SOA 的 NXDOMAIN 转为可缓存对象，无 SOA 的仍抛出、由 `query()` 转为不缓存的 NXDOMAIN 响应。`cache_size: 0` 关闭缓存。

### 7.3 ConcurrentResolver

`type: concurrent` 组合之前已经注册的 Resolver。每个直接子 Resolver 返回带 Answer 的 NOERROR 响应后，可按配置执行 Action 的 `on_resolver(context, response)`，用于收集测速结果、改写候选响应或标记候选无效（标记后该候选被丢弃）；否定/失败响应不会执行这些动作。最终结果再交给路由 `after` 动作。

配置意图是：

- `wait_all: false`：首个带 Answer 的 NOERROR 结果后取消剩余任务。
- `wait_all: true`：收齐所有候选，以便 Speedcheck 等 Action 二次选择。

结果通过 AnyIO memory object stream 按完成顺序消费。`wait_all: false` 在首个带 Answer 的 NOERROR 响应后取消剩余任务；`wait_all: true` 在整体 `timeout` 内收集候选。无论哪种模式，超时前已经完成的结果都会保留；没有成功响应时优先返回 NXDOMAIN，再回退其他否定响应。嵌套 ConcurrentResolver 使用独立 Context，只把本层直接上游写入候选集。

## 8. Routing 与标签匹配

路由只在查询前使用 `RequestMatcher`：

- `query_types`：与 DNS 类型文本比较，不区分配置大小写。
- `domain_include`：请求域名标签必须至少命中一个；没有 Geo 数据或没有标签时 fail-closed。
- `domain_exclude`：命中任一标签即排除。

这些字段保存的是标签，不是字面域名。例如 `cn`、`google`、`category-ads-all` 来自 GeoSite 数据。

响应 Action 还会使用 `ResponseIPMatcher`：

- `ip_include` / `ip_exclude`：匹配 GeoIP 或 IPSet 标签，不是字面 IP。
- `asn_include` / `asn_exclude`：匹配整数 ASN（例如 `asn_include: [64500]`）。

IP 标签与 ASN include 维度之间采用 OR；任一 exclude 命中都会否决整体响应。缺少 Geo 标签时仍可按 ASN 匹配，配置了 include 但没有任何可匹配数据时 fail-closed。

### Geo 数据

| 配置字段 | 运行时类 | 说明 |
|---|---|---|
| `geodata.geosite` | `GeoSite` | mmap 加载 MARISA BytesTrie；把域名规范化为小写、标签逆序后做前缀查询 |
| `geodata.geoip` | `GeoIP` | 读取自定义标签字符串/列表或标准 MaxMind country 结构 |
| `geodata.asn` | `GeoIP` | 读取 `autonomous_system_number` |
| `geodata.ipset` | `IPSet` | 读取本地可信 pickle/radix 文件，把覆盖网段的 data key 合并为标签 |

`GeoManager` 是进程级单例，在 Master 事件循环初始化。Worker 线程中的 Request/Response 标签查询共享这些只读数据对象。

## 9. Action 处理阶段

Action 基类有三个 hook：

| Hook | 调用位置 | 当前内置实现 |
|---|---|---|
| `on_request` | Router 的 `before` | `static`、`log` |
| `on_resolver` | ConcurrentResolver 每个直接子响应完成后 | `replace`、`speedcheck`、`filter` |
| `on_response` | Router 的 `after` | `speedcheck`、`https`、`fallback` |
| `on_subquery` | Router 的 after 动作之后、子查询完成时 | 无 |

Action 放在没有实现的阶段时是 no-op，不会报错。

### static

按查询类型返回配置的 IPv4/IPv6 地址，TTL 固定为 86400，并设置 `context.stop`。默认地址是 `127.0.0.1` 和 `::1`。它只对 A/AAAA 生成记录；其他类型会得到空 NOERROR 响应。

### log

在 before 阶段记录自定义文本、查询名、查询类型和客户端地址。

### replace

只在 ConcurrentResolver 的 `actions` 中执行。先用 `match_name` 匹配请求域名或响应 CNAME 标签，再按 `replace_map` 顺序寻找命中的响应 IP 标签。替换时保留原 IP 在 `prefixlen` 之外的主机位，再叠加到每个目标基址。

示例：原地址 `192.0.2.42`，目标基址 `198.51.100.0`，`ipv4_prefixlen: 24`，结果为 `198.51.100.42`。

### speedcheck

`on_resolver` 收集 A/AAAA 候选 IP，启用测速时进行 ICMP ping 和/或多个 TCP 端口连接测试；任一方式成功即采用该结果。排序倍率先按 `tag_multipliers` 的配置顺序寻找首个命中的标签，再查 `asn_multipliers`，均未命中时为 `1`。`on_response` 优先选择有有效 RTT（非空且有限，包括 `0`）的 IP，按原始 RTT 乘倍率升序排序，并保留与最佳结果标签集合相同、加权 RTT 差不超过 `threshold` 的前 `max_num` 个地址。所有候选都没有有效 RTT 时，仅按倍率升序保留前 `max_num` 个地址，不限制标签集合，忽略 `threshold`。缺失、无穷大及 NaN 均不算有效 RTT；原始 RTT 不变。ICMP 和 TCP 均关闭时不发起新探测，但上下文已有的有效 RTT 仍按上述规则优先使用。

重建应答时保留排序顺序，UDP/TCP 监听器序列化时关闭记录随机打乱，避免发送阶段破坏排序。

ICMP 与 TCP 测速均返回毫秒。`ping_config.privileged` 控制 icmplib 使用非特权模式还是原始 ICMP socket。任一探测成功后取消其余探测；结果缓存 1800 秒，键包含 IP、是否 ICMP、ICMP 特权模式、TCP 端口集合和超时配置。同一事件循环内的同键请求还会复用正在进行的测速任务。

### https

仅处理 HTTPS RR。它按配置移除 ipv4hint/ipv6hint，并从 ALPN 中只移除 `h3`（保留其他协议，若只剩 h3 则删除整个 ALPN 参数）；之后根据域名和响应 IP 标签决定是否查询 `ech_domain` 并注入 ECH。

`match_ip` 的判定依赖 hint 派生的 IP 标签。当 `match_ip` 配置了判定条件、`match_name` 命中且记录不带任何 hint（响应无 IP 标签）时，Action 改为在 on_response 阶段设置 A 记录子查询（请求 qname，当前路由 resolver 执行，不占用即得），在 on_subquery 阶段用 A 应答自带的 IP 标签完成 match_ip 判定，再统一执行清理与 ECH 注入。A 应答无 IP（否定应答）时按 include 不匹配处理——不注入 ECH，清理照常；子查询槽位被其他动作占用时退回 on_response 内联处理（空标签判定）。副作用：无 hint 域名的清理延迟到子查询阶段，其后的 after 动作在 on_response 看到未清理响应；after 链中后续动作设置 `stop` 会跳过子查询，延迟重写不执行。

`add_ech: false` 会跳过 ECH 查询和注入，但仍允许 hint/ALPN 清理。字段名必须写 `ech_domain`；误写为 `ech` 会在严格配置校验阶段报错。HTTPS、Replace、Speedcheck 和 Fallback 都通过重建 Answer/RRset 实现 copy-on-write，不修改共享候选或缓存对象。

### fallback

当应答为 NOERROR 但没有任何 IP（NODATA 空应答）时，或所有测速结果都不可用时，根据域名/CNAME 标签映射，用静态 IPv4/IPv6 地址替换当前响应。测速判定依赖前面已经在 ConcurrentResolver 中执行过 `speedcheck.on_resolver`；若无测速数据但存在 IP 候选（未启用测速），视为未失败，Fallback 直接跳过。

### filter

只在 ConcurrentResolver 的 `actions` 中执行，用于丢弃被污染或不合预期的候选。每条过滤项先以 `match_name` 匹配请求域名与当前候选 CNAME 链组成的标签链（仅 A/AAAA/HTTPS 查询生效），再用 `match_ip` 检查响应 IP；两项都命中时把候选标记为 `invalid`，ConcurrentResolver 会跳过被标记的候选。域名排除标签命中的过滤项直接跳过，不会标记。配置条目在启动时深拷贝，运行期不会修改配置对象。

### 子查询（on_subquery）

on_response 阶段的动作可以把 `Context.for_subquery(context, qname=None, rdtype=None)` 的返回值赋给 `context.subquery` 来发起一次子查询；新请求默认沿用原查询的 qname/rdtype/rdclass、监听器与客户端地址，传入 qname/rdtype 可查询其他目标。

Router 在 after 动作循环结束后检查 `context.subquery`：已设置且路由配置了 resolver 时，以 `resolver.query(subquery.request, None)` 执行一次查询。`context=None` 使 ConcurrentResolver 跳过其 `actions`（on_resolver）与候选写回，子查询不重复外层加工；嵌套解析器现有的 `is_subquery` 打标行为不受影响。

查询完成后，Router 按配置顺序对全部 after 动作调用 `on_subquery(context, response)`，`response` 为子查询响应（同时写入 `context.subquery.response`）；某动作设置 `context.stop` 会中断后续回调。子查询结果不自动替换 `context.response`，是否改写最终响应由动作自行决定。

边界：主响应非 NOERROR 时 after 动作本就被跳过，因此不会触发子查询；after 动作设置 `context.stop` 提前结束路由时同样跳过；路由没有 resolver 时忽略子查询；子查询抛出异常时降级为 SERVFAIL 响应并继续回调；子查询只执行一轮，on_subquery 中再设置 `context.subquery` 不会再次触发。当前唯一内置消费者是 `https` Action（记录无 hint 时以 A 记录子查询获取 IP 标签）。

## 10. 缓存与共享状态

项目中有四类缓存设计：

1. Master DNS Answer 缓存：`AnswerCache` 直建实例（跨线程锁 + TLRUCache，ttu 取 Answer 自身 expiration），容量由顶层 `cache_size` 控制，`0` 关闭；`fetch` 的同键 in-flight 合并覆盖全部监听器。
2. 全局 ECHConfig 缓存：Master 创建 100 项、300 秒的 TTLCache 并通过 `set_ech_cache` 注入，所有 Worker 的 HTTPClient 共享；键为域名规范化文本，不含实例标识。
3. 测速缓存：Master 创建 10000 项、1800 秒的 TLRUCache，保存跨 Worker 可共享的数值结果。
4. Resolver 应答缓存：plain 与 aiodns 各自的 `cache_size` 控制容量，经 `AnswerCache.shared` 按完整解析器配置注册并跨 Worker 线程共享，同名但配置不同的解析器相互隔离；aiodns 挂在 `resolve()` 边界（ECH 引导查询亦受益），plain 挂在 `query()` 出口前。

`AnswerCache`（`utils/cache_async.py`）是三类 Answer 缓存的统一载体：存储层为线程锁串行化的 TLRUCache（墙钟计时、按应答自身 TTL 过期），实现 MutableMapping 协议，对外提供 `read`/`write` 异步读写与 `fetch(key, fn)`（未命中执行 fn 并写入，同键并发经 `cached()` in-flight 表合并为一次执行）。

Master Answer 缓存键包含 `(qname, type, class, listener, ECS)`；客户端地址不入键，因为当前上游查询不转发客户端地址。写入与读取均复制 Answer，读取副本按剩余存活时间刷新所有 section 的 TTL。dispatch 仅运行于 Master 主循环，同缓存键的未命中请求会共享一次进行中的 Worker 查询；持久缓存中仍只保存最终 `Answer`，不会保存 Task/Future。

ECHConfig、测速与 AnswerCache.fetch 统一使用 `utils.cache_async.cached` decorator：cachetools 缓存只保存最终结果，同一事件循环内的同键调用复用进行中的 Task，不同事件循环之间不会共享 Future/Task（跨循环首次填充可能各执行一次，锁内 setdefault 保证只落一份）。ECHConfig 与测速缓存为进程级全局（Master 经 `set_cache`/`set_ech_cache` 注入，Action/HTTPClient 层经 getter 解耦），只保存跨线程安全的不可变值。

## 11. 配置与启动顺序约束

Pydantic 在加载阶段同时验证字段形状、未知字段、重复名称和名称引用。Resolver 仍按配置顺序创建：

- `plain` 可引用 `nameservers` 列表中的任意已注册名称，不受其声明位置影响。
- `concurrent` 只能引用位于它之前的 Resolver；前向引用直接导致配置加载失败。
- 路由和 ConcurrentResolver 中不存在的 Action、路由中不存在的 Resolver、plain 中不存在的 Nameserver 都直接导致配置加载失败。
- Listener、Nameserver、Resolver、Action 和路由名称都必须唯一。

建议始终按“Nameserver/Action → 叶子 Resolver → ConcurrentResolver → 路由”的依赖方向组织配置，并在部署前做引用完整性检查。

## 12. 离线工具

### `utils.convert`

读取 mihomo `geosite.dat`、`tags/geosite/*.txt` 和 `tags/geoip/*.txt`，生成：

- `geosite.json`
- `geosite.trie`
- `geoip.radix`

运行示例：

```bash
uv run python -m utils.convert --geodata-path tags/geosite.dat --tag-path tags --output-path tags/output
```

输出目录不存在时会自动创建，并在首次运行写出全部三个产物。

### `utils.fetch_ip`

工具只在显式 CLI 调用时联网，所有 HTTP 请求配置超时和状态码检查；四个结果使用临时文件原子替换，失败时不会破坏已有输出。

### `utils.gws`

通过 PTR 或 `*.1e100.net` 名称模式推导 Google 数据中心基址，并把结果合并写入 JSON：

```bash
uv run python -m utils.gws --domain domains.txt --ip ips.txt --output output.json
```

## 13. 已知边界

- 当前只实现标准 UDP/TCP DNS Listener；HTTP/DoH Listener 配置会被拒绝。
- aiodns 不支持 ECS（pycares 无法注入 EDNS Client Subnet 选项），需要固定 ECS 时使用 plain 解析器；Resolver 级 `cache_size` 已激活为应答缓存容量。
- UDP `use_tricks` 的报文特征过滤属于兼容性策略，不等同于完整的 DNS 投毒检测。

## 14. 验证现状

本轮整改的发布门禁为：

- `uv run ruff format --check .`
- `uv run ruff check .`
- `uv run ty check`
- `uv run pytest`

`utils/mihomo` 是 protobuf 生成代码，在 Ruff、格式化和 Ty 配置中排除；其余手写运行时代码、测试和工具全部纳入检查。
