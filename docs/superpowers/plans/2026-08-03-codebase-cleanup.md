# smartdns 全面重构实现计划

> **For agentic workers:** 用 superpowers:executing-plans 或 subagent-driven-development 按阶段执行。每个阶段（Phase）是一个独立可提交、可验证的单元；阶段内条目按文件组织。

**Goal:** 在不改变对外行为契约的前提下，修复 smartdns 代码库中的阻断级/正确性 bug、清理冗余日志与死代码、补全未完成功能（连接池、停机路径）、并统一 DRY/类型/lint，使整个包可解析、可导入、通过 ruff/ty 与冒烟测试。

**Architecture:** smartdns 是基于 anyio/asyncio 的多进程 DNS 代理：Master 分发 → 多 Worker（portal）→ 规则路由（before actions → resolver → after actions）。上游 nameserver（tcp/udp/curl-DoH）、resolver（plain/aiodns/concurrent）、routing（geoip/geosite/ipset）、actions（static/replace/https/log）各成模块，均由对应 Manager 装配。配置走 pydantic-settings（YAML）。

**Tech Stack:** Python 3.14 / anyio + asyncio / dnspython 2.8 / curl_cffi 0.15 / aiodns / pydantic v2 + pydantic-settings / loguru / generic_connection_pool / cachetools / typer / ruff + ty。

## Global Constraints

- Python `>=3.14`；所有改动须通过 `uv run ruff check smartdns/` 与 `uv run ty check smartdns/`。
- 日志统一 loguru；**热路径禁止 INFO 级整对象打印**，禁止打印原始 wire 字节、完整 Config、ECH 密钥等敏感/大对象；`logger.exception` 内不再重复插值 `{e}`。
- 行为契约保持：nameserver/resolver/listener/action 的公开方法签名（尤其 dnspython 要求的 `async_query`/socket ABC 签名）不得破坏。
- 缓存策略本次**只修污染**（actions copy-on-write），全局缓存键忽略客户端身份的设计**保留现状**、仅加注释说明。
- 停机本次**最小修复**：实现缺失的 `stop()` 并在关闭路径串联 `stop_all`，**不**加 SIGINT/SIGTERM 信号处理。
- 连接池本次**保留并补全**（不删除）。
- 无既有测试；本计划为高风险逻辑修复新增 `tests/` 下的针对性 pytest，用 ruff/ty/import 冒烟作为机械改动的安全网。每阶段结束提交一次。

---

## 验证基线（起点，已采集）

- `py_compile`：2 处语法错误 —— `nameservers/_pool.py:4`、`resolvers/manager.py:40`。
- `ruff`：122 项（66 TC 类型导入、42 E501、4 ASYNC109、3 RET504、2 UP047、1 F821、1 PLW0603、1 UP035、1 W292、2 invalid-syntax）。
- `ty`：34 项（多为 `utils/cache_async.py` 动态属性赋值）。

每阶段验证命令统一为：
```bash
uv run python -m compileall -q smartdns/        # 语法
uv run ruff check smartdns/                       # lint
uv run ty check smartdns/                         # 类型
uv run pytest -q                                  # 测试（Phase 0 起可用）
```

---

## Phase 0 — 恢复可运行 + 测试脚手架

**Files:**
- Modify: `smartdns/resolvers/manager.py:38-40`
- Modify: `smartdns/nameservers/client.py:7,63`
- Modify: `smartdns/nameservers/_pool.py`（最小可解析修复；完整补全见 Phase 3）
- Create: `tests/conftest.py`, `tests/test_import_smoke.py`
- Modify: `pyproject.toml`（pytest-asyncio 配置）

**改动：**
- `resolvers/manager.py`：`resolvers=self.` → `resolvers=self`（把 ResolverManager 自身传给 `ConcurrentResolver`；Phase 5 再做惰性解析）。
- `client.py`：`from dns.name import from_text` → `from dns.name import Name, from_text`（消除 F821）。
- `_pool.py`：修正签名为可解析且语义完整的最小版：
  ```python
  def __init__(self, ssl_context=None, tls: bool = False, connect_timeout: float = 5.0) -> None:
      self._tls = tls
      self._ssl_context = ssl_context
      self._connect_timeout = connect_timeout
  ```
  （Phase 3 补 `create`/`dispose` 并接入。）
- `pyproject.toml`：`[tool.pytest.ini_options]` 加 `asyncio_mode = "auto"`。

**测试（import 冒烟，覆盖全部子模块）：**
```python
# tests/test_import_smoke.py
import importlib, pkgutil
import smartdns

def test_all_submodules_import():
    failed = []
    for m in pkgutil.walk_packages(smartdns.__path__, "smartdns."):
        try:
            importlib.import_module(m.name)
        except Exception as e:  # noqa: BLE001
            failed.append(f"{m.name}: {e!r}")
    assert not failed, "\n".join(failed)
```

**Verify:** `compileall` 干净；`ruff` 无 invalid-syntax/F821；`pytest -q` 冒烟通过。
**Commit:** `fix: 修复阻断级语法错误与未定义名，补测试脚手架`

---

## Phase 1 — Nameserver 生命周期与基类契约

**Files:** `smartdns/nameservers/base.py`, `curl.py`, `tcp.py`, `udp.py`

**改动：**
- `base.py`：
  - `BaseNameserver` 增加可继承默认 `async def stop(self) -> None: pass`（替代 `raise NotImplementedError`，解决 TCP/Curl 关闭崩溃根因）。
  - `is_always_max_size()` 下放：`BaseNameserver` 不再无条件 `True`；Curl 覆写返回 `True`，TCP/UDP 走 `AddressAndPortNameserver` 的默认。
  - 清理 `__init__` 注释残留（`# super().__init__(...)`），`BaseAddressNameserver` 用显式双基类初始化并加注释说明 MRO 意图。
- `curl.py`：实现 `async def stop()`（释放/关闭 session，见 Phase 2）；`answer_nameserver` 收窄为 `str`（`assert self.host is not None`），`answer_port` 收窄为 `int`。
- `tcp.py`：实现 `async def stop()`（关闭池，见 Phase 3；此阶段先 `pass` 占位或关闭 `self._pool`）；`__init__(self, config: TCPNameserverConfig)` 补类型注解（TYPE_CHECKING 导入）。

**Verify:** `ty`（answer_* 类型收窄消除告警）；冒烟。
**Commit:** `refactor(nameservers): 统一生命周期契约，修复 stop() 缺失与 answer_* 返回类型`

---

## Phase 2 — Curl ECH per-nameserver 会话隔离（P1 critical）

**根因：** 所有 `CurlNameserver` 共享 `HTTPClient` 的单一 `AsyncSession`，逐请求改 `session.curl_options[CurlOpt.ECH]`；`curl_cffi` 异步 `request/get/post` **不接受 per-request curl_options**（`_request_once` 始终用会话级 `self.curl_options`）→ 并发竞态 + ECH 跨请求/跨 nameserver 泄漏。

**方案：** 每个 `CurlNameserver` 独占一个 `AsyncSession`。ECH 域名 per-nameserver 固定，故其会话的 `curl_options[ECH]` 只承载本 nameserver 的 ecl，无跨污染。

**Files:** `smartdns/nameservers/client.py`, `smartdns/nameservers/curl.py`

**改动：**
- `client.py`：抽出会话构建为工厂，供每个 curl nameserver 独立建会话：
  ```python
  def create_session(self, extra_options: dict[CurlOpt, object] | None = None) -> AsyncSession:
      """按客户端基础配置创建一个独立的 AsyncSession（每个 curl 上游各持一个，避免共享可变状态）。"""
      opt = self._base_curl_options()          # 由现 start() 内联逻辑抽出：DOH/RESOLVE/DNS_*/ECH="true"
      if extra_options:
          opt.update(extra_options)
      return AsyncSession(
          headers={"Accept": "application/dns-message"},
          max_clients=self.config.max_clients,
          http_version=CurlHttpVersion.V2TLS,
          default_headers=True,
          impersonate="chrome",
          curl_options=opt,
      )
  ```
  `start()` 改为调用 `create_session()` 建自身默认 session（若 HTTPClient 仍需自持一个）；`get_curl()` 保留兼容或标注废弃。`get_ech_key` 缓存键纳入 resolver 标识、入口统一 `domain` 为规范文本。
- `curl.py`：
  - `start()`：`self._curl = self._client.create_session()`（本 nameserver 独占）。
  - `async_query`：在**自身** session 上按请求设置 ECH（同域名值一致，安全）；**删除**打印 ECH 密钥与 `curl_options` 的 debug（`:62,:64`）。
  - `stop()`：`await self._curl.close()`（curl_cffi AsyncSession 关闭）。
  - 去掉 `str(self.url)`（`:79`）与 `str(config.host)`（`:17`）冗余；非 200 分支不再走 `logger.exception`（拆分 ValueError 与真实异常，避免自造异常打全栈重复记录）。

**测试：**
```python
# tests/nameservers/test_curl_session_isolation.py
# 断言两个不同 ech 域名的 CurlNameserver 使用不同的 AsyncSession 实例，
# 且各自 session.curl_options 不被对方影响（用 fake client.create_session 返回可区分对象）。
```

**Verify:** `ruff`/`ty`/冒烟 + 新测试。
**Commit:** `fix(curl): 每上游独占会话消除 ECH 共享竞态与密钥日志泄漏`

---

## Phase 3 — 连接池补全（P1，保留并补全）

**目标：** 让 `_pool.py` 成为可用的 anyio TCP 流连接管理器，并在 `tcp.py` 中真正接入（`pool_size>0` 时复用连接）。

**Files:** `smartdns/nameservers/_pool.py`, `smartdns/nameservers/tcp.py`, 确认 `smartdns/models/nameserver.py` 的 `pool_size` 字段

**改动：**
- `_pool.py`：实现基于 anyio 流的管理器（endpoint=`(host, port)`，连接=anyio stream）：
  ```python
  from anyio import connect_tcp
  from anyio.abc import SocketStream
  from generic_connection_pool.asyncio import BaseConnectionManager

  TcpEndpoint = tuple[str, int]

  class TCPStreamConnectionManager(BaseConnectionManager[TcpEndpoint, SocketStream]):
      def __init__(self, ssl_context=None, tls: bool = False, connect_timeout: float = 5.0) -> None:
          self._tls = tls
          self._ssl_context = ssl_context
          self._connect_timeout = connect_timeout

      async def create(self, endpoint: TcpEndpoint) -> SocketStream:
          host, port = endpoint
          with fail_after(self._connect_timeout):
              return await connect_tcp(host, port, tls=self._tls, ssl_context=self._ssl_context)

      async def dispose(self, endpoint: TcpEndpoint, conn: SocketStream) -> None:
          await conn.aclose()

      async def check_aliveness(self, endpoint: TcpEndpoint, conn: SocketStream) -> bool:
          return conn.extra(SocketAttribute.raw_socket, None) is not None
  ```
  （aliveness 以 `StreamAlivenessCheckingMixin` 思路实现；实现时读 `generic_connection_pool/asyncio/pool.py` 确认 `ConnectionPool.connection(endpoint, timeout=...)` 异步上下文管理器签名。）
- `tcp.py`：
  ```python
  from generic_connection_pool.asyncio import ConnectionPool

  async def _create_pool(self) -> ConnectionPool:
      return ConnectionPool(self._manager, max_size=self._pool_size, total_max_size=self._pool_size * 4)

  async def async_query(self, ...):
      if self._pool is not None:
          async with self._pool.connection(endpoint=(self.host, self.port), timeout=timeout or self.timeout) as raw_sock:
              sock = AnyioStreamSocket(raw_sock, use_tricks=self._use_tricks)
              return await dns.asyncquery.tcp(request, where=self.address, timeout=timeout or self.timeout, port=self.port, sock=sock, ...)
      # 非池化路径保留现逻辑
  ```
  `stop()` 关闭池（`await self._pool.close()`）；`_connect`/`self._sock` 死代码删除；透传 `one_rr_per_rrset`/`ignore_trailing` 形参（不再硬编码 `ignore_trailing=True`）；`timeout or self.timeout` 改显式 `None` 判断。

**风险提示：** 这是本计划**最高风险项**（DNS-over-TCP 连接复用的分帧/存活边界，无网络测试较难覆盖）。附带本地回环 echo/DNS server 的集成测试；若复用连接出现分帧问题，回退为"每查询新建连接但由池限流"的保守策略。

**测试：** `tests/nameservers/test_tcp_pool.py` —— 用本地 asyncio echo server 验证 create/复用/dispose/aliveness 与并发上限。

**Verify:** `ruff`/`ty`/冒烟 + 池测试。
**Commit:** `feat(nameservers): 补全 TCP 连接池并接入 async_query`

---

## Phase 4 — Listeners 正确性（P1）

**Files:** `smartdns/listeners/udp.py`, `tcp.py`, `_socket.py`, `manager.py`, `base.py`

**udp.py（critical + major）：**
- **关闭忙循环**：`while True` 内 `except Exception` 对 `ClosedResourceError`/`CancelledError`（`anyio.get_cancelled_exc_class()`）单独 `break`/重抛，仅对单包解析错误 `continue`。
- 删除循环后**不可达**的 `await self._listener.aclose()`（`:90`）。
- **未判 None 响应**：`if response is not None:` 再 `send_udp`（与 TCP 一致）。
- **IPv4 host 崩溃**：仅当 `self._family == AF_INET6` 才 `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)`。
- **套接字生命周期**：建 socket/bind 迁到 `start()`（`from_socket` 需预绑定，start 内先 bind 再 wrap）；`stop()` 兜底关闭 `self._sock`。
- 热循环 `logger.exception`（每包全栈）降为单行 `debug`/`warning`。
- 删死代码：`self.timeout` 重复赋值、`else AF_INET6` 不可达三元、注释掉的 `create_udp_socket` 块；Windows `reuse_port` 忽略时给 warning。

**tcp.py（major）：** 正常断开单独捕获 `EOFError`→`debug`/`break`；去重复 `aclose`（保留 `async with` 或 `finally` 之一）；`getpeername` 解包置于 try 内并防 `None`；`:59` 原始字节 debug 精简。

**_socket.py：** 删 `sendto` 的 `destination is None` 死分支（dnspython 恒传 destination）；抽超时→`Timeout` 样板为 `@asynccontextmanager`；统一 `getpeercert` 返回 `None`；补形参/返回类型注解（对齐 dnspython ABC）；删/降热路径 debug（建 stream、每次收发）与"先 error 再 raise 又被上层重复记录"的双重日志。

**manager.py：** `match` 显式处理/拒绝 `"http"`（`HTTPListenerConfig`，避免 `case _` 在任务组内 `ValueError` 连带取消其它监听器）；tcp/udp 两分支改类型→类字典分派；删 `logger.debug(self.config)`；`start_all(handler)` 与全链路补 `Handler = Callable[[Request], Awaitable[Message | None]]` 类型。

**base.py：** 改 `abc.ABC` + `@abstractmethod`；子类 `__init__` 形参类型与基类一致（消除收窄重写）；补 handler 类型。

**测试：** `tests/listeners/test_udp_handler.py` —— handler 返回 `None` 时不发包不崩溃；`af_for_address` IPv4 分支不设 V6ONLY（可单测辅助函数）。

**Verify:** `ruff`/`ty`/冒烟 + 测试。
**Commit:** `fix(listeners): 修复 UDP 关闭忙循环/V6ONLY 崩溃/None 响应及 TCP 断开误报`

---

## Phase 5 — Resolvers 正确性（P1）

**Files:** `smartdns/resolvers/aiodns.py`, `concurrent.py`, `plain.py`, `manager.py`, `base.py`

**aiodns.py：** import 并处理 `ARES_ENOTFOUND` → 构造 NXDOMAIN 响应（参考 plain 的 NXDOMAIN 分支），修复 NXDOMAIN→SERVFAIL；`resolve` 与 `query` 二选一记录（下层不再"既 error 又 raise"）；`raise e`→裸 `raise`；`code = e.args[0] if e.args else None`；`self.nameservers[0]` 前判空（或配置加 `min_length=1`）；删 wire 字节 debug；`query_type_map.update` 移到 module 级；修复复制粘贴 docstring；`make_answer` 补 `-> Answer`；删死配置 `cache_size`；统一 `self.name`。

**concurrent.py：** 修复 `invalid`/`rcode` 耦合导致的否定应答被吞：
- 逻辑改为——收到 NOERROR 立即返回；否则记录一个"最佳否定应答（NXDOMAIN 等）"候选，全部上游结束后回退返回该候选而非一律 SERVFAIL。
- 改 anyio 原生首成功模式（memory object stream 或 TaskHandle 自行竞速），去掉 `asyncio.as_completed` 依赖；命中后 `tg.cancel()`。
- 上游**惰性解析**：不在 `start()` 即 `self._manager.get(name)`，改到 `query()` 时解析（消除启动顺序依赖）；或 manager 改两阶段（先全构造入 dict 再统一 start）。
- 补 `request: Request` 注解与 import；`coros`→`handles`；精简每请求 debug。

**plain.py：** **删** `logger.warning(f"rinfo:...")`（`:49`，每请求 WARNING 遗留调试）；`ecs` 转 `dns.edns.ECSOption` 写入 `ednsoptions` 或删字段；改 `self.use_edns(config.edns, payload=1232, options=...)` 修 payload=0；删死配置 `cache_size`（或真正构造 `dns.resolver.Cache`）；去重复 `raise_on_no_answer`；双 `super()` 加注释显式化；`logger.exception` 去 `{e}`。

**manager.py：** 惰性解析配合 concurrent（见上）；删 `logger.debug(self.config)`；`start_all`/`stop_all` 补 `-> None`。

**base.py：** 改 `abc.ABC` + `@abstractmethod`。

**测试：** `tests/resolvers/test_negative_answers.py` —— aiodns ENOTFOUND→NXDOMAIN（mock pycares 抛 `DNSError(ARES_ENOTFOUND)`）；concurrent 全上游返回 NXDOMAIN 时返回 NXDOMAIN 而非 SERVFAIL。

**Verify:** `ruff`/`ty`/冒烟 + 测试。
**Commit:** `fix(resolvers): 修复 NXDOMAIN→SERVFAIL、concurrent 否定应答丢弃与启动顺序依赖`

---

## Phase 6 — Routing 正确性（P1）

**Files:** `smartdns/routing/router.py`, `geoip.py`, `geosite.py`, `ipset.py`, `manager.py`

**router.py：**
- 未知/缺失 resolver：`get()` 返回 None 时 `logger.warning` 告警；`query` 阶段无 resolver 时区分处理——不应静默 `return True` 吞请求，改为 `return False` 交下一路由（并确保 `after` 语义正确）。
- 删死子条件 `or context.stop`（`:77-80`，恒假不可达）。
- `query_types` 大小写归一化：两侧 `.upper()`；`query_types` 为 None 时不计算 `to_text`。
- `domain_include` 改 fail-closed（`country is None` 时不应放行全部）。
- 修误导性文案（"在 resolver 阶段停止请求"分不清无 resolver / 上游错误）；两个"不匹配域名"分支区分文案；`:39` 空 matcher 每请求 DEBUG 降噪。
- 四处 INFO 级 `{context.request}` 整报文打印 → 降 DEBUG 或只打 `qname/rdtype` 摘要（隐私 + 性能）。
- `async def match` 无 `await` → 视情况改普通方法或保留并注释。`not context.response` → `is None`。

**geoip.py：** 显式处理 MaxMind **dict** 记录形状（`{"country": {"iso_code": ...}}`），未命中已知形状时告警（修复静默失效）；`lookup` 边界 `str(ip)`；`.exists()` 冗余清理并在加载失败时告警。

**geosite.py：** `normalize` 与 `utils/convert.py` 抽为**共享**一份（防漂移）；`create` 若保留则复用 `normalize`（修潜在未规范化 bug），否则连同 `save`/注释死代码一并删除（当前 trie 由 convert.py 构建，`create/save` 为死代码——按"全面重构/YAGNI"删除，保留 `load`/`lookup`）；`decode("ascii")` 对非 punycode 标签的异常防护。

**ipset.py：** 删死代码 `add/remove/create/clear/save`（保留 `load`/`lookup`）；`pickle.load` 加注释说明来源可信（本地缓存）。

**manager.py：** `lookup_ip(ip: str | IPvAnyAddress)` 类型放宽对齐下游。

**测试：** `tests/routing/test_router_no_resolver.py`（无 resolver 不吞请求）；`tests/routing/test_geoip_shapes.py`（dict 记录能取到 country）。

**Verify:** `ruff`/`ty`/冒烟 + 测试。
**Commit:** `fix(routing): 修复 resolver 黑洞、geoip 记录形状与域名 fail-open，清理死代码`

---

## Phase 7 — Actions 正确性 + 缓存污染修复（P1）

**Files:** `smartdns/actions/base.py`, `manager.py`, `https.py`, `replace.py`, `log.py`, `static.py`

**base.py（架构根因）：** 可选 hook（`on_request`/`on_response`/`pre_upstream`/`post_upstream`/`on_subquery`）默认改 `pass`（no-op），消除 before/after 错配触发 NotImplementedError→SERVFAIL；`stop()` 默认 `pass`；删除全项目无派发的 `pre_upstream`/`post_upstream`/`on_subquery` 悬空 hook。

**manager.py：** 补 `case "print"`（实现极简 `PrintAction` 或从 `ActionConfig` 联合移除 `PrintActionConfig`——本计划选**实现** `PrintAction`，与 config 兼容）；`match` 改**类模式** `case StaticActionConfig():` 收窄静态类型（修 ty 报错与构造器误传联合）；加 `from __future__ import annotations`；`get(name)` 去冗余 `None`；名字重复静默覆盖加 warning；删/精简 `logger.debug(self.config)` 与大对象 info。

**https.py（缓存污染 + 多记录）：**
- 循环内 `return` → `continue`（多条 HTTPS RR 都处理）。
- 排除域名/CNAME 判断（与 rr 无关）移到循环外只判一次。
- **copy-on-write**：不再就地改 `rr.params._odict` / 复用缓存 rdata；用公开 API 重建 rdata/RRset（避免污染线程安全缓存的共享对象）。
- 空 ALPN 边界：h3 为唯一 ALPN 时移除 ALPN 参数而非写空 `ids=()`。
- `except Exception` 后 `return`/`break`，避免对每个 IP 重复 `get_ech_key`。
- `:33` 非 HTTPS 早退前的整 `response` debug 删除；`:94` 措辞从 replace 复制粘贴残留改正；`ids: tuple[bytes, ...]`。

**replace.py（缓存污染）：**
- **copy-on-write**：`rrset.clear()` 就地改写 → 构造新 rrset 替换（不污染缓存）。
- A/AAAA 两分支抽公共逻辑去重。
- 空替换集（默认 `set()`）保护：不 `clear()` 成空 NODATA。
- `new_ip + offset` 越界 `AddressValueError` 防护。
- 排除域名/CNAME 与 https 抽共享 helper；循环不变量 `if self.exclude is not None` 外提。

**log.py：** 形参类型 `LogActionConfig`；`self.text` 要么在 `on_request` 使用、要么删除；`:22` info 级整 `context.request` 打印降级/摘要。

**static.py：** 简化 `make_response(make_query(...), ...)`（删对 query 无效的 `set_rcode`）；`__init__`/`start` 双日志合并（构造函数不打日志）。

**共享 helper：** 新建（或放 actions/base.py）`_is_excluded(request, response, exclude) -> bool` 供 https/replace 复用。

**测试：** `tests/actions/test_https_multi_rr.py`（多条 HTTPS RR 均处理、原 rrset 不被就地改写）；`tests/actions/test_replace_cow.py`（替换不污染传入的共享 Answer、空集不产生 NODATA、offset 越界被处理）。

**Verify:** `ruff`/`ty`/冒烟 + 测试。
**Commit:** `fix(actions): copy-on-write 消除缓存污染，修复多记录处理与 hook 契约`

---

## Phase 8 — Core 生命周期与缓存（P1/P2）

**Files:** `smartdns/core/master.py`, `worker.py`, `cache.py`, `smartdns/utils/cache_async.py`, `smartdns/main.py`

**master.py：** 统一 `listener_manager` 命名（删 `self._listener_manager` 死属性）；新增 `async def stop()` 调 `listener_manager.stop_all()` 并触发各 worker `stop()`，在关闭路径（ExitStack 回调）调用（**不加信号**）；热路径 INFO 整对象 → debug/摘要；`if self._cache:` 统一 `is not None`；`logger.exception` 去 `{e}`。

**worker.py：** 新增 `async def stop()` 依次 `nameservers/resolvers/actions.stop_all()` + `client.stop()`；`self._actions: ActionManager | None = None` 在 `__init__` 声明；`SERVFAIL` 响应抽常量/辅助（3 处）；`process()` 补 `-> None`；每请求 INFO 整 Context → debug；`Config` 移入 `TYPE_CHECKING`；`if ctx.response:` → `is not None`；`logger.exception` 去 `{e}`。

**cache.py：** 三段 rrset 循环用 `itertools.chain` 合并；删注释掉的 `CacheManager` 骨架；形参 `maxsize`→与基类一致的 `max_size`；`ttl` 加 `max(0, ...)` 防御；键构造处**加注释**说明"忽略客户端身份为已知限制，本次不改"；`self.get`/`super().put` 统一 `self`。

**cache_async.py：** 删死代码 `cachedmethod`（全项目仅用 `cached`）；`get_event_loop()`→`get_running_loop()`；`from typing import ContextManager`→`contextlib.AbstractContextManager`（UP035）；`except ValueError: pass` 至少 `logger.debug` 一笔；参数化 `Task`/`Future` 泛型；`cached` 的 `wrapper.cache_lock` 正确反映传入 lock。

**main.py：** `logger.debug(f"配置文件加载成功: {config}")` → 只打印摘要（不 dump 整 Config）；配置失败 `logger.exception` + `raise typer.Exit(1)`（非零退出）；`FilePath` 注解说明（Typer 不校验存在性）；去与 master 重复的 `backend_options`（或注释 Windows uvloop 生效性）。

**测试：** `tests/core/test_lifecycle.py` —— `Worker.stop()` 调用各 manager `stop_all` 与 `client.stop`（mock 断言）。

**Verify:** `ruff`/`ty`/冒烟 + 测试。
**Commit:** `feat(core): 补全 Master/Worker 停机路径，清理缓存与热路径日志`

---

## Phase 9 — 日志与死代码清扫（P2）

**Files:** 全包（系统性一遍）

**改动（清单式，逐条 grep 核对）：**
- 各 Manager 的 `logger.debug(self.config)`（nameservers/listeners/resolvers/actions 四处）→ 删或改为名称/数量摘要。
- 所有 `logger.exception(f"...{e}")` 去掉 `{e}`。
- 原始 wire 字节 / 完整 `Request`/`Response`/`Context`/`Config` / ECH 密钥的日志——统一降级为摘要或删除。
- nameservers/manager 的"监听器"措辞 → "上游"。
- "下层记录 + 上层重复记录"的双重日志统一到一处。
- 删除各文件注释掉的死代码块（`_socket.py`、`udp.py`、`http.py`、`cache.py` 等中残留）。
- `context.py`：模型层日志下沉——`from_answer` 的 `logger.info(rcode)` 移到 resolver/worker 层或用惰性 `logger.info("...{}", rcode)`；删 `logger.debug(response)`。

**Verify:** `grep` 确认无 `logger.debug(self.config)`、无 `logger.exception(f"...{e}")`、无 wire 字节打印；`ruff`（E501 大幅下降）/`ty`/冒烟。
**Commit:** `refactor: 系统清理冗余/泄漏日志与注释死代码`

---

## Phase 10 — Models DRY 与一致性（P3）

**Files:** `smartdns/models/*.py`

**改动：**
- 抽中间基类：`nameserver.py` 的 `AddressNameserverConfig`（address/port/use_tricks，UDP/TCP 继承）；`resolver.py` 的共享字段基类（Plain/AioDNS 的 nameservers/rotate/edns，注意 cache_size 默认不同）；`listener.py` 的 host/port 基类（并统一 host 可选性）；`action.py` 的 `text` 基类（Log/Print）与共享 `exclude`。
- 删全项目无 alias 的 `populate_by_name=True`（nameserver/listener/resolver/action 四处）。
- `default=[]`/`default={...}`/`default=Model()` → `default_factory=...`（config.py、action.py 等）。
- `listener.py`：`Literal["udp"] | Literal["tcp"]` → `Literal["udp","tcp"]`；HTTP host 可选性与 Do53 统一。
- `http.py`：删注释死代码块；`max_clients` `ge=0`→`ge=1`。
- `context.py`：`from_ip` 的 `resolver: str | None = None` 注解；`ext: dict[str, Any]`；`models→routing` 反向依赖改惰性导入（解耦分层）；`make_answer` 硬编码 NOERROR 加注释或透传 rcode。
- `config.py`：删 `model_config` 里死配置 `yaml_file`（统一用 `config_file`）；确认 settings 源顺序（env vs yaml，按当前语义保留并注释）。
- `rule.py`/`action.py`：修复复制粘贴 docstring / description 与默认值矛盾（`ech_domain`）。
- `geodata.py`：`FilePath` fail-fast 语义确认（保留，加注释）。

**Verify:** `ty`/冒烟（模型改动最易破坏下游，冒烟测试是关键网）。
**Commit:** `refactor(models): 抽取基类去重，统一默认值/字段一致性与分层解耦`

---

## Phase 11 — Lint / 类型收尾（P3）

**Files:** 全包

**改动：**
- `ruff check --fix`（安全修复）先跑；余下手动：
  - 66 个 TC001/002/003：类型专用导入移入 `if TYPE_CHECKING:` 块。
  - `RET504`（不必要赋值后返回）、`UP047`（PEP 695 泛型函数语法）、`UP035`、`PLW0603`（global）、`W292`（文件尾换行）、残余 `E501`。
- `ty` 34 项收敛：`cache_async.py` 的 wrapper 动态属性——用 `functools.wraps` + 明确类型或 `typing.cast`/协议消除 `unresolved-attribute`；删多余 `# type: ignore`。
- 若有确需保留的规则，在 `pyproject.toml` 的 `ignore` 列表登记并注释原因。

**Verify（最终门禁）：**
```bash
uv run python -m compileall -q smartdns/     # 干净
uv run ruff check smartdns/                    # 0 error（或仅登记的 ignore）
uv run ty check smartdns/                      # 0 error
uv run pytest -q                               # 全绿
```
**Commit:** `style: 收敛 ruff/ty 诊断，类型导入移入 TYPE_CHECKING`

---

## 最终交付

- 分支 `refactor/codebase-cleanup`，每阶段一次提交，历史清晰可回溯。
- 全部门禁绿：compileall / ruff / ty / pytest。
- 未做（本次范围外，已在代码注释标注）：全局缓存键纳入客户端身份、SIGINT/SIGTERM 信号处理。

## Self-Review 记录（覆盖性核对）

- 2 处语法错误 → Phase 0 ✓；F821 → Phase 0 ✓；tcp `_create_pool` 缺失 → Phase 3 ✓。
- curl ECH 竞态 → Phase 2 ✓；停机崩溃/生命周期 → Phase 1/8 ✓；UDP 忙循环 → Phase 4 ✓。
- 否定应答→SERVFAIL（aiodns/concurrent/router）→ Phase 5/6 ✓。
- 缓存污染（actions）→ Phase 7 ✓；geoip 记录形状 → Phase 6 ✓。
- 冗余日志/凭据泄漏 → Phase 9（+各阶段就近处理）✓；死代码 → Phase 6/8/9 ✓。
- DRY（4 manager 分派、模型基类）→ Phase 4/5/7/10 ✓；lint/类型 → Phase 11 ✓。
- 连接池"保留并补全" → Phase 3 ✓；缓存"只修污染" → Phase 7 + Phase 8 注释 ✓；停机"最小修复" → Phase 8 ✓。
