# SmartDNS 配置参考

本文档对应当前 `smartdns/models` 与实际管理器实现。完整示例见根目录 `example.yaml`。

## 1. 顶层结构

```yaml
worker_count: 1
cache_size: 10000
log_level: INFO
geodata: {}
client: {}
listeners: []
nameservers: []
resolvers: []
actions: []
routing: []
```

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `worker_count` | int >= 1 | CPU 数 | 独立 Worker 线程/事件循环数量 |
| `cache_size` | int >= 0 | 10000 | Master Answer 缓存容量；0 表示关闭 |
| `log_level` | str | INFO | TRACE/DEBUG/INFO/SUCCESS/WARNING/ERROR/CRITICAL；CLI 日志经队列异步写入，DEBUG/TRACE 可查看详细上下文 |
| `geodata` | object | 空 | GeoIP、ASN、GeoSite 和 IPSet 文件 |
| `client` | object | 空 | curl HTTP/DoH 客户端的公共选项 |
| `listeners` | list | 空 | 客户端监听器 |
| `nameservers` | list | 空 | 供 plain Resolver 使用的底层上游 |
| `resolvers` | list | 空 | 可供路由选择的解析策略 |
| `actions` | list | 空 | 请求/响应加工动作 |
| `routing` | list | 空 | 按顺序执行的路由规则 |

顶层及嵌套 YAML 字段拼写错误都会触发校验失败；重复名称、错误引用和 Resolver 前向引用也在加载阶段拒绝。

## 2. Geo 数据

```yaml
geodata:
  geosite: tags/output/geosite.trie
  geoip: tags/output/geoip.metadb
  asn: tags/output/asn.mmdb
  ipset: tags/output/geoip.radix
```

所有字段均可省略，但一旦配置就必须指向已存在的文件。

- `geosite` 产生域名标签，供 `domain_include`/`domain_exclude` 使用。
- `geoip` 和 `ipset` 产生 IP 标签，供 `ip_include`/`ip_exclude` 使用。
- `asn` 产生整数 ASN，配置使用 `asn_include: [64500]` / `asn_exclude: [64501]`。

若没有 GeoSite 数据，带 `domain_include` 的路由会 fail-closed；最后必须配置无 matcher 的兜底路由。

## 3. HTTPClient

```yaml
client:
  max_clients: 256
  dns_cache_ttl: 300
  shuffle: true
  doh: https://dns.google/dns-query
  doh_verify: true
  hosts:
    dns.example.com:
      - 192.0.2.53
      - "2001:db8::53"
  resolver:
    name: http-bootstrap
    type: aiodns
    nameservers: [1.1.1.1, 8.8.8.8]
    timeout: 2
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `max_clients` | 256 | 每个 Worker 中每个 DoH 会话的最大并发请求数；会话名额排队计入 DNS 查询时限 |
| `hosts` | null | 转为 curl `RESOLVE` 的静态映射，按各 curl 上游 URL 的端口生效 |
| `dns_cache_ttl` | 300 | curl DNS 缓存秒数 |
| `shuffle` | true | 是否让 curl 打乱 DNS 地址 |
| `doh` | null | curl 自身解析目标主机时使用的 DoH URL |
| `doh_verify` | true | 上述 DoH URL 的证书验证 |
| `resolver` | null | 获取 ECHConfig 时使用的内嵌 AioDNSResolver |

只有使用字符串形式的 `nameservers[].ech` 或 HTTPS Action 注入 ECH 时，才需要 `client.resolver`。

## 4. Listener

当前运行时可用类型只有 UDP 和 TCP。

```yaml
listeners:
  - name: udp-main
    type: udp
    host: "::"
    port: 5335
    timeout: 5
    reuse_port: false

  - name: tcp-main
    type: tcp
    host: "::"
    port: 5335
    timeout: 5
    reuse_port: false
```

| 字段 | 适用类型 | 默认值 | 说明 |
|---|---|---|---|
| `name` | 全部 | 必填 | 日志和 Request 中的监听器名称 |
| `type` | 全部 | 必填 | `udp` 或 `tcp` |
| `host` | 全部 | null | 监听地址；UDP 的 null 会转换为 `::` |
| `port` | 全部 | 必填 | 1-65535 |
| `timeout` | 全部 | 5 秒 | 单个请求的接收、限流排队、处理和回写共用的整体超时 |
| `reuse_port` | UDP/TCP | false | Windows UDP 会忽略并告警；TCP 交给 AnyIO |

UDP 回包会遵循客户端声明的 EDNS payload；没有 EDNS 时上限为 512 字节。较大响应会返回带 `TC=1` 的合法截断报文，客户端随后可通过 TCP 获取完整结果。TCP Listener 支持完整的最大 65535 字节 DNS 消息，不受 UDP payload 限制。

UDP 在收到完整请求后开始计时，TCP 在收到帧首字节后开始计时，接收剩余帧和等待并发名额均消耗请求预算；排队到期后丢弃请求。TCP 空闲连接单独按 `timeout` 计时，接受连接后等待连接名额也受此时限约束。

`type: http` 尚未实现，配置加载阶段会明确拒绝。

## 5. Nameserver

### UDP

```yaml
- name: udp-cloudflare
  type: udp
  address: 1.1.1.1
  port: 53
  timeout: 3
  repeat: 0
  use_tricks: false
```

- `repeat` 为额外重复次数，0 表示只发一次。
- `use_tricks` 启用最多五次接收和简单报文特征过滤。
- 上游 UDP 响应带 `TC=1` 时，plain Resolver 会自动对同一地址和端口改用 TCP 重试。

### TCP

```yaml
- name: tcp-google
  type: tcp
  address: 8.8.8.8
  port: 53
  timeout: 5
  pool_size: 4
  use_tricks: false
```

- `pool_size: 0` 表示每次查询新建连接。
- 大于 0 时按 Worker 创建独立连接池。
- 连接池健康检查只做非破坏性 `MSG_PEEK`，不会关闭可复用连接。
- `use_tricks` 启用尽力而为的 OOB 前缀发送；实现不会切换 AnyIO 底层 socket 的阻塞状态，后端不支持或发送失败时会回退为完整报文的普通异步发送。

### TLS（DoT）

```yaml
- name: tls-cloudflare
  type: tls
  address: 1.1.1.1
  port: 853
  timeout: 5
  server_name: cloudflare-dns.com
  fingerprint: chrome:stable
  verify: true
  pool_size: 4
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `port` | 853 | DoT 标准端口 |
| `server_name` | 域名地址取地址本身；IP 为空 | TLS SNI 与证书验证锚点；IP 地址不发 SNI（RFC 6066） |
| `fingerprint` | chrome:stable | utls 指纹预设（`chrome:131/142/146/148/150/stable`），伪装浏览器 ClientHello；`null` 表示标准 ClientHello |
| `verify` | true | 证书校验；`address` 为 IP 且未配 `server_name` 时开启校验会在启动时报错 |
| `pool_size` | 0 | 同 TCP：0 表示每次查询新建连接并握手，大于 0 时按 Worker 创建连接池复用握手完成的加密连接 |

分帧与 DNS over TCP 相同（2 字节长度前缀），收发复用 `dns.asyncquery.tcp`。握手由内置的 utls（BoringSSL）驱动，连接池健康检查为非破坏性 `MSG_PEEK`（peek 到 TLS 密文视为存活）。

### DNSCrypt

```yaml
- name: dnscrypt-cryptostorm
  type: dnscrypt
  stamp: sdns://AQcAAAAAAAAADTk0LjE5OC40MS4yMzUgMTNyrVlWMsJBa4cvCY-FG925ZShMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz
  timeout: 5
  tcp_only: false
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `stamp` | 必填 | `sdns://` DNSCrypt stamp，包含地址（端口省略时默认 443）、提供者名称与 Ed25519 公钥；配置加载期解析，非法格式直接报错 |
| `tcp_only` | false | 强制所有查询走 TCP |
| `pool_size` | 0 | 已弃用；为兼容旧配置仍接受该字段，但 DNSCrypt 每次 TCP 查询都使用新连接 |

协议实现 DNSCrypt v2 的 X25519 + XChaCha20_DJB-Poly1305，仅接受 es_version=2 证书。`dnsstamps` 解析 stamp，PyNaCl 生成客户端密钥并校验证书；由于 PyNaCl 未公开该协议所需的 XChaCha20 `crypto_box` 接口，还需要可动态加载的 libsodium。系统安装 libsodium 后，若无法通过默认库路径找到它，请将 `SMARTDNS_LIBSODIUM_PATH` 设为库文件绝对路径（Windows 建议使用 [libsodium 官方 MSVC 预编译包](https://download.libsodium.org/libsodium/releases/)中的 64 位动态库）。缺少该库时 DNSCrypt 上游会在启动时明确报错。`dnsstamps` 1.4.1 对少见的长提供者名称解析不完整；配置校验会拒绝这类 stamp，避免静默截短。

启动时向上游自身 `地址:端口` 发送普通 DNS TXT 查询获取证书（UDP 失败或截断回退 TCP），选取 serial 最高的有效证书；证书临期时自动刷新。普通查询走 UDP，应答 TC 时由 dnspython 以 `max_size=True` 改走 TCP。解密后校验响应 nonce、填充、DNS ID 和问题是否匹配。DNSCrypt TCP 每条连接只处理一次查询。stamp 可从解析器提供方或 dnscrypt 公共解析器列表获取。

### curl DoH

```yaml
- name: doh-cloudflare
  type: curl
  url: https://cloudflare-dns.com/dns-query
  host: cloudflare-dns.com
  timeout: 5
  want_get: false
  verify: true
  ech: true
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `url` | 必填 | DoH URL |
| `host` | URL 主机 | HTTP Host 头 |
| `want_get` | false | false 使用 `application/dns-message` POST，true 使用 GET `?dns=` |
| `verify` | true | 目标 HTTPS 证书验证 |
| `ech` | true | 字符串时从该域名查询 ECHConfig；布尔值不触发显式查询 |
| `fingerprint` | chrome | curl-cffi 指纹模拟目标（如 `chrome`、`chrome131`、`safari`、`firefox`），伪装 TLS/HTTP2 ClientHello；`null` 表示不模拟。未知值在配置加载期报错 |

## 6. Resolver

Nameserver 会在 Resolver 启动前全部注册，因此 plain Resolver 可引用 `nameservers` 列表中的任意名称。Resolver 自身按列表顺序创建，所以必须先定义叶子 Resolver，再定义消费它们的 ConcurrentResolver。

### aiodns

```yaml
- name: direct-cn
  type: aiodns
  nameservers:
    - 223.5.5.5
    - 119.29.29.29
  port: 53
  timeout: 2
  rotate: true
  edns: true
  tcp: false
  tries: 3
  max_queries: 16
  nodata_ttl: 300
```

`nameservers` 只接受 IP 地址；误填 Nameserver 名称会在配置加载时失败。aiodns 不支持 ECS（pycares 无法注入 EDNS Client Subnet 选项），需要固定 ECS 时请使用 plain 解析器。

`max_queries` 默认 16（至少 1），限制每个 Worker 中此解析器的原生并发查询和通道数。通道按需创建并复用，每次独占租用一个通道；取消时调用该通道的 `cancel()`，停止此查询的底层重试并归还名额，不取消其他通道的查询。pycares 的默认事件线程模式会为通道创建线程，增大此值会增加资源占用。

`cache_size` 控制应答缓存容量（默认 10000，`0` 关闭）：缓存挂在 `resolve()` 边界，路由路径与 `client.resolver` 的 ECH 引导查询共用；条目按应答自身 TTL 过期（NODATA 为 `nodata_ttl`），持久层为相同完整配置跨 Worker 共享的 `AnswerCache` 实例。同名但配置不同的解析器使用不同缓存；配置完全一致的顶层解析器和 `client.resolver` 会共享缓存。

`nodata_ttl` 是空应答（NODATA，如 IPv4-only 域名查 AAAA）写入缓存的秒数：pycares 的 ENODATA 不携带 SOA，无记录可压 TTL，需显式指定负缓存时长，0 表示不缓存。

### plain

```yaml
- name: doh
  type: plain
  nameservers:
    - doh-cloudflare
  rotate: true
  edns: true
  ecs: 203.0.113.0/24
  lifetime: 5
```

`nameservers` 填前面 `nameservers[].name`。`lifetime` 是实际查询总时限。`cache_size` 控制应答缓存容量（默认 10000，`0` 关闭）：条目按应答自身 TTL 过期（负应答取 authority 区 SOA），持久层由相同完整配置的解析器跨 Worker 共享，同名但配置不同的解析器使用不同实例；同一事件循环内的同键并发查询经 `cached()` 合并为一次上游查询。

所有 PlainResolver 引用都会在配置加载时校验，不存在的名称不会延迟到运行期跳过。

### concurrent

```yaml
- name: race
  type: concurrent
  resolvers:
    - direct-cn
    - doh
  actions:
    - speed
  wait_all: true
  timeout: 5
```

- `resolvers` 只能引用列表中位于它之前的 Resolver。
- `actions` 只在直接子 Resolver 返回带 Answer 的 NOERROR 响应后调用 `on_resolver`。
- Speedcheck 需要候选完整时通常配置 `wait_all: true`。
- `wait_all: false` 在首个带 Answer 的 NOERROR 响应后取消剩余任务。
- `wait_all: true` 在整体 `timeout` 内收集已完成候选；超时不会丢弃已经完成的快速结果。

监听器把单请求的单调时钟截止时间传入 Worker 和派生子查询。收集阶段同时考虑解析器自身 `timeout` 与外层剩余预算，为后续加工和回包预留 10%（至少 50ms）；嵌套收集也受当前任务的外层期限约束。Router 的 after 动作和子查询共用剩余预算，到期时保留最后一个完整应答并返回，监听器的整体超时继续作为硬上限。

启用 Master 缓存时，同键未命中请求合并查询，但每个客户端仍有独立的超时。共享查询在未取得答案时使用仍未到期等待者的最晚期限，已有答案后使用最早期限收尾；首个客户端取消不会中断其他等待者，后到客户端也不会延长解析器自身 `timeout`。嵌套候选必须完成外层全部 `actions` 才能参与最终排序，外层丢弃嵌套胜者时整个分支丢弃。

嵌套胜者通过检查后，其他候选的后处理也受软期限约束；到期只丢弃未完成检查的候选，保留已通过检查的胜者及其测速信息。

## 7. Matcher

### 请求/域名 matcher

```yaml
match_name:
  domain_include: [google, cloudflare]
  domain_exclude: [cn, category-ads-all]
  query_types: [A, AAAA]
```

同一结构用于 `routing[].matcher`、Replace/HTTPS 的 `match_name` 和 Fallback map。标签可来自原查询域名；部分响应 Action 也会检查 CNAME 链标签。

### 响应 IP matcher

```yaml
match_ip:
  ip_include: [cloudflare, fastly]
  ip_exclude: [cn]
  asn_include: [64500]
  asn_exclude: [64501]
```

`ip_include`/`ip_exclude` 是标签，ASN 字段是整数。include 维度之间采用 OR，任一 exclude 命中会否决整个响应。

## 8. Action

### log

```yaml
- name: access-log
  type: log
  text: dns-query
```

放入路由 `before`。

### static

```yaml
- name: block
  type: static
  ipv4: [0.0.0.0]
  ipv6: ["::"]
  ttl: 86400
```

放入路由 `before`；A/AAAA 之外的类型会得到空 NOERROR。`ttl` 为静态应答的 TTL（秒），默认 86400。

### replace

```yaml
- name: replace-cdn
  type: replace
  match_name:
    domain_exclude: [cn]
  replace_map:
    - match_ip:
        ip_include: [cloudflare]
      ipv4_prefixlen: 24
      ipv6_prefixlen: 64
      ipv4: [198.51.100.0]
      ipv6: ["2001:db8:100::"]
```

必须放入 ConcurrentResolver 的 `actions`，路由 `after` 不会调用它的 `on_resolver`。

### speedcheck

```yaml
- name: speed
  type: speedcheck
  ping_config:
    ping: true
    privileged: false
    port: [443]
    timeout: 0.3
  match_ip: {}
  tag_multipliers:
    cloudflare: 0.8
    cn: 1.0
  asn_multipliers:
    15169: 1.2
  max_num: 2
  threshold: 50
```

`privileged: true`（默认）使用原始 ICMP socket；设为 `false` 时使用 icmplib 的非特权 ICMP 模式。原始模式要求进程具备平台要求的 root、管理员权限或 `CAP_NET_RAW`。它只影响 ICMP，不影响 TCP 端口测速。

通常同时放在 ConcurrentResolver 的 `actions` 和路由 `after`：前者采样，后者择优。若只放在路由 `after`，没有 `context.ip_infos` 可供选择。

`tag_multipliers` 和 `asn_multipliers` 均为可省略的字典，默认为空。先匹配 IP 的标签；多个配置标签命中时，按字典顺序采用第一个。没有配置标签命中时再查 ASN，均未命中时倍率为 `1`。倍率必须为大于 `0` 的有限数；小于 `1` 提高优先级，大于 `1` 降低优先级，标签与 ASN 的倍率不叠乘。

只要候选中存在有效 RTT（非空的有限数，包括 `0`），就优先选择有有效 RTT 的 IP，并按 `实际 RTT × 倍率` 升序排序。仍只保留与最佳 IP 标签集合相同的地址，`threshold` 限制它们与最佳 IP 的加权 RTT 差，`max_num` 限制数量；没有有效 RTT 的 IP 不会因倍率更低而抢占它们的位置。若所有候选都没有有效 RTT，则直接按倍率升序保留前 `max_num` 个 IP，不限制标签集合，忽略 `threshold`。缺失 RTT、失败返回的无穷大及 NaN 均视为没有有效 RTT。原始 RTT 和测速缓存不变，返回的地址保持排序顺序，同分时保留候选收集顺序。

设 `ping_config.ping: false` 且省略 `port`（或设 `port: []`）可关闭全部主动测速；此时不发起探测，但上下文中已有的有效 RTT 仍会优先用于排序。若 ICMP 关闭但配置了 TCP 端口，仍会测量 TCP RTT。排序方式取决于候选实际是否有有效 RTT；即使启用了测速，只要全部候选没有有效 RTT，也会按倍率升序选择。

### https

```yaml
- name: tune-https
  type: https
  remove_hint: true
  remove_h3: true
  add_ech: true
  enable_subquery: true
  match_name:
    domain_exclude: [cn]
  match_ip:
    ip_include: [cloudflare]
  ech_domain: crypto.cloudflare.com
```

字段名是 `ech_domain`，不是 `ech`。`add_ech: false` 只执行 hint/ALPN 清理，不查询或注入 ECH。
`enable_subquery` 默认为 `true`。设为 `false` 时不发起 A 子查询，也不为 HTTPS 空应答合成记录；已有 HTTPS 记录仍会清理 hint/h3。若 `match_ip` 有筛选条件而记录无 hint，则缺少可判定的 IP，不注入 ECH。

已有 HTTPS 记录的 hint/h3 清理先于 ECH 获取和 A 子查询等待完成。ECH 或子查询到期时，主应答及其 Master 缓存条目仍保留清理结果。
启用子查询且 HTTPS 查询返回 `NOERROR` 但无 HTTPS 记录时，Action 会以同一路由解析器查询原域名的 A 记录；A 地址命中 `match_ip` 且取得 ECHConfig 后，返回仅含 ECH 参数的 `HTTPS 1 .` 记录。合成记录的 TTL 不超过 A 应答、原空应答的剩余有效期及 300 秒；A 查询无地址、匹配失败或获取 ECH 失败时保留原空应答。此路径只使用 A 记录，不查询 AAAA。
合成记录没有 ALPN 参数；按 [RFC 9460 的 HTTPS 映射](https://www.rfc-editor.org/rfc/rfc9460.html#section-9)，其默认 SVCB ALPN 集合为 `http/1.1`。

### fallback

```yaml
- name: fallback
  type: fallback
  map:
    - match_name:
        domain_include: [google]
      ipv4: [203.0.113.10]
      ipv6: ["2001:db8::10"]
      ttl: 86400
```

Fallback 依赖此前的 Speedcheck 采样；当应答为 NOERROR 但没有任何 IP（NODATA 空应答），或所有候选测速均失败时，替换为映射中的静态地址，TTL 用映射的 `ttl`（秒，默认 86400）。

### filter

```yaml
- name: filter
  type: filter
  filters:
    - match_name:
        domain_exclude: [facebook, dropbox]
      match_ip:
        ip_exclude: [facebook, twitter]
```

必须放入 ConcurrentResolver 的 `actions`。每条过滤项先用 `match_name` 匹配请求域名与候选 CNAME 链标签（仅对 A/AAAA/HTTPS 查询生效），再用 `match_ip` 检查响应 IP 标签；两者都命中时该候选被标记为无效并从竞速结果中丢弃。`domain_exclude` 命中的过滤项整体跳过，常用于豁免真实解析结果就带这些标签的域名。

## 9. Routing

```yaml
routing:
  - name: block-ads
    matcher:
      domain_include: [category-ads-all]
    before: [block]

  - name: domestic
    matcher:
      domain_include: [cn]
    resolver: direct-cn

  - name: default
    resolver: race
    before: [access-log]
    after: [speed, fallback, tune-https]
```

规则严格按顺序执行。建议：

1. 静态拦截和特殊域名放最前。
2. GeoSite 分流规则放中间。
3. 最后一条无 matcher 的兜底规则必须引用有效 Resolver。
4. NXDOMAIN/SERVFAIL 会终止路由，不会尝试后续规则或 after 动作。

## 10. 示例配置的两种运行模式

`example.yaml` 是覆盖全部组件类型的完整参考配置：UDP/TCP 监听、四种 Nameserver（UDP/TCP/TLS/curl DoH）、三种 Resolver（aiodns/plain/concurrent）、七种 Action 与完整路由链。除注释掉的 `geodata` 外不依赖本地文件，复制后即可通过配置模型加载；无 Geo 数据时，带 `domain_include` 的路由 fail-closed，请求由末尾兜底路由处理。

若要启用标签分流：

1. 先生成/准备 `tags/output/geosite.trie`、GeoIP 和 ASN 文件。
2. 取消 `example.yaml` 中 `geodata` 注释。
3. 广告拦截与 `cn` 分流规则、Replace/HTTPS/Filter 等标签匹配 Action 均已就位并被正确引用，启用 Geo 数据后自动生效。

## 11. 启动前自检

可用下面的命令只加载配置，不启动监听器和外部网络请求：

```powershell
@'
from pathlib import Path
from smartdns.models.config import Config

Config.set_config_file(Path("example.yaml"))
cfg = Config()
print(
    len(cfg.listeners),
    len(cfg.nameservers),
    len(cfg.resolvers),
    len(cfg.actions),
    len(cfg.routing),
)
'@ | uv run python -
```

这会验证字段、本地文件路径、重复名称、跨组件引用和 ConcurrentResolver 声明顺序；它不会验证上游网络可达性。
