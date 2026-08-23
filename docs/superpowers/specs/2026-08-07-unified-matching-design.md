# 统一匹配功能设计

## 目标

将当前分散在 `Router`、Action helpers 和各响应 Action 中的匹配逻辑统一到 `smartdns.routing.matcher`，同时保持现有生产行为、Action 返回值需求和选择优先级。

本次工作只统一匹配逻辑，不重构 Resolver、Geo 数据加载、Action 的 DNS 记录类型能力检查，也不修改无关工作区文件。

## 现状与约束

- `Router.match()` 是当前请求匹配的生产实现，负责 query type、domain include 和 domain exclude。
- `routing/matcher.py` 是尚未接线的草稿，当前存在 query type 类型不一致、`None` 运算、include fail-open、结果依赖记录顺序和 ASN 类型不一致等问题，不能直接接入。
- 响应匹配分散在 Replace、HTTPS、Fallback 和 `actions/_helpers.py` 中。
- Router 在解析响应前匹配，Action 在解析响应后匹配，因此不能用一个 `match_context()` 同时承担两个阶段。
- Replace 需要返回具体的 `(IPInfo, ReplaceActionMap)`，Fallback 需要过滤后的 IP 列表，HTTPS 只需要布尔值；统一层必须提供小粒度原语，不能只提供整体响应布尔判断。
- 保留 Replace 当前的“先按 replace map 顺序，再按响应 IP 顺序”选择优先级。

## 设计方案

采用“小粒度匹配原语 + 逐调用点接线”方案。

### 数据模型

- 保留 `RequestMatcher`，作为 `Rule.matcher` 的请求配置类型。
- 保留 `ResponseCnameMatcher` 和 `ResponseIPMatcher`，分别表达响应域名标签和 IP/ASN 标签条件。
- 将 `ResponseIPMatcher.asn_include`、`asn_exclude` 定义为 `set[int] | None`，与运行时 `IPInfo.asn: int | None` 一致。
- `IPInfo` 和 `NameInfo` 归属 `models/geodata.py`；`models/context.py` 使用导入，不重复定义。
- 字段说明明确 domain/cname/ip include 与 exclude 保存的是 GeoSite、GeoIP 或 IPSet 标签，而不是字面域名或 IP 地址。

### 中央匹配模块

`smartdns.routing.matcher` 提供以下职责明确的接口：

1. 请求匹配
   - 将 `Request.rdtype` 转为大写文本，与配置侧的大写文本比较。
   - 配置了 include 但请求没有 Geo 标签时 fail-closed。
   - exclude 仅在请求有 Geo 标签时判断，避免 `None` 集合运算。
   - exclude 可以否决 include 命中。

2. 域名标签链匹配
   - 统一遍历请求域名和响应 CNAME 的 `NameInfo.country` 标签。
   - 提供“是否命中任一给定标签”的小原语。
   - `_helpers.is_included()` 与 `_helpers.is_excluded()` 保留兼容接口，但内部委托该原语。

3. 单 IP 匹配与 IP 列表过滤
   - 分别判断 `IPInfo.country` 标签和 `IPInfo.asn`。
   - `country is None` 时仍继续判断 ASN。
   - 响应级 include 使用 OR：IP 标签或 ASN 任一 include 命中即可满足 include。
   - exclude 全局优先；任一响应项命中 exclude，整体响应匹配失败。
   - 配置了 include 但所有响应项均未命中时 fail-closed。
   - 无匹配条件时匹配；没有响应项但配置了 include 时不匹配。
   - 结果不依赖 CNAME/IP 的遍历顺序。

4. 删除 `match_context()`
   - 该接口混合了解析前请求阶段和解析后响应阶段，且无法表达各 Action 所需的不同返回值，因此不保留。

## 接线范围

### Router

保留 `Router.match(Context)` 作为兼容外观和日志边界：

- matcher 为 `None` 时仍匹配所有请求。
- matcher 非空时委托 `routing.matcher.match_request()`。
- 不将 Router 改为调用响应匹配接口。

### Action helpers

`is_included()` 和 `is_excluded()` 改为域名标签链原语的薄包装，保持 Replace、HTTPS 和 Fallback 的现有调用方式。

### HTTPS

将响应 IP 标签判断委托中央响应匹配原语，保持只返回布尔结果的行为。

### Fallback

- 域名 include/exclude 继续通过 helpers 使用中央域名链匹配。
- IP 筛选使用单 IP 判断或过滤原语，保留具体命中 IP 列表。

### Replace

保留外层 `replace_map` 优先、内层 `ip_infos` 顺序。每个候选项只复用中央单 IP 标签判断，不使用会丢失映射和优先级信息的整体响应布尔接口。

### 不纳入本次统一的逻辑

Static、Replace、HTTPS、Fallback 对 A、AAAA 和 HTTPS RR 类型的判断属于 Action 能力 guard，不属于配置驱动的路由匹配，不强行包装成 Matcher。

## 错误与边界语义

- `matcher=None`：请求匹配全部。
- include 未配置：不施加 include 限制。
- include 已配置但运行时标签或响应项缺失：fail-closed。
- exclude 已配置但运行时标签缺失：不命中 exclude，也不抛异常。
- 同一项同时命中 include 与 exclude：exclude 优先。
- 多条 CNAME/IP 中任一项命中 exclude：整体响应匹配失败。
- 多个 include 维度之间采用 OR；include 与 exclude 两组之间采用“满足 include 且不命中 exclude”。
- `IPInfo.country=None` 不影响对 `IPInfo.asn` 的判断。

## 测试与验证

新增或补充以下测试：

- 请求 query type：大小写归一化、匹配和不匹配。
- 请求域名：无 geodata、include 命中、exclude 命中、include/exclude 冲突。
- 域名链：请求域名命中、CNAME 命中、空响应、多个 CNAME、顺序独立性。
- 响应 IP：空列表、include 命中/未命中、exclude 命中、多个 IP、顺序独立性。
- ASN：整数配置命中、未命中、`country=None` 时仍匹配 ASN。
- Router：无 matcher、委托结果和既有日志边界。
- Actions：HTTPS 布尔匹配、Fallback IP 过滤、Replace map-first 优先级回归。

验证顺序：

1. PyCharm/LSP 检查修改文件。
2. 使用 PyCharm reformat 对修改文件执行项目格式化。
3. 运行 `ruff check`；按项目既有约束不运行 `ruff format`。
4. 运行 `ty check`。
5. 运行匹配相关目标测试。
6. 运行完整测试套件。
7. 若有失败，定位根因并修复后重复相应验证。

## 工作区保护

- 不覆盖或回退用户已有未提交改动。
- 不修改 `config.yaml`、`.idea/`、`docs.zip` 等无关内容。
- 不擅自暂存、提交或推送代码。
