# SmartDNS 配置参考

本文档对应当前 `smartdns/models` 与实际管理器实现。完整示例见根目录 `example.yaml`。

## 1. 顶层结构

```yaml
worker_count: 1
cache_size: 10000
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
| `max_clients` | 65536 | 每个 Worker 创建 curl session 时的最大客户端数 |
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
| `timeout` | 全部 | 5 秒 | 单个请求从接收、处理到回写的整体超时 |
| `reuse_port` | UDP/TCP | false | Windows UDP 会忽略并告警；TCP 交给 AnyIO |

UDP 回包会遵循客户端声明的 EDNS payload；没有 EDNS 时上限为 512 字节。较大响应会返回带 `TC=1` 的合法截断报文，客户端随后可通过 TCP 获取完整结果。TCP Listener 支持完整的最大 65535 字节 DNS 消息，不受 UDP payload 限制。

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
| `fingerprint` | null | utls 指纹预设（`chrome:131/142/146/148/150/stable`），伪装浏览器 ClientHello；缺省为标准 ClientHello |
| `verify` | true | 证书校验；`address` 为 IP 且未配 `server_name` 时开启校验会在启动时报错 |
| `pool_size` | 0 | 同 TCP：0 表示每次查询新建连接并握手，大于 0 时按 Worker 创建连接池复用握手完成的加密连接 |

分帧与 DNS over TCP 相同（2 字节长度前缀），收发复用 `dns.asyncquery.tcp`。握手由内置的 utls（BoringSSL）驱动，连接池健康检查为非破坏性 `MSG_PEEK`（peek 到 TLS 密文视为存活）。

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
  nodata_ttl: 300
```

`nameservers` 只接受 IP 地址；误填 Nameserver 名称会在配置加载时失败。aiodns 不支持 ECS（pycares 无法注入 EDNS Client Subnet 选项），需要固定 ECS 时请使用 plain 解析器。

`cache_size` 控制应答缓存容量（默认 10000，`0` 关闭）：缓存挂在 `resolve()` 边界，路由路径与 `client.resolver` 的 ECH 引导查询共用；条目按应答自身 TTL 过期（NODATA 为 `nodata_ttl`），持久层为同名解析器跨 Worker 共享的 `AnswerCache` 实例。注意：与顶层 aiodns 解析器同名的 `client.resolver`（如均叫 `114dns`）会共享同一份缓存。

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

`nameservers` 填前面 `nameservers[].name`。`lifetime` 是实际查询总时限。`cache_size` 控制应答缓存容量（默认 10000，`0` 关闭）：条目按应答自身 TTL 过期（负应答取 authority 区 SOA），持久层是同名解析器跨 Worker 共享的 cachetools 实例，同一事件循环内的同键并发查询经 `cached()` 合并为一次上游查询。

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
```

放入路由 `before`；A/AAAA 之外的类型会得到空 NOERROR。

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
  max_num: 2
  threshold: 50
```

`privileged: true`（默认）使用原始 ICMP socket；设为 `false` 时使用 icmplib 的非特权 ICMP 模式。原始模式要求进程具备平台要求的 root、管理员权限或 `CAP_NET_RAW`。它只影响 ICMP，不影响 TCP 端口测速。

通常同时放在 ConcurrentResolver 的 `actions` 和路由 `after`：前者采样，后者择优。若只放在路由 `after`，没有 `context.ip_infos` 可供选择。

### https

```yaml
- name: tune-https
  type: https
  remove_hint: true
  remove_h3: true
  add_ech: true
  match_name:
    domain_exclude: [cn]
  match_ip:
    ip_include: [cloudflare]
  ech_domain: crypto.cloudflare.com
```

字段名是 `ech_domain`，不是 `ech`。`add_ech: false` 只执行 hint/ALPN 清理，不查询或注入 ECH。

### fallback

```yaml
- name: fallback
  type: fallback
  map:
    - match_name:
        domain_include: [google]
      ipv4: [203.0.113.10]
      ipv6: ["2001:db8::10"]
```

Fallback 依赖此前的 Speedcheck 采样；只有所有候选测速均失败时才替换。

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
