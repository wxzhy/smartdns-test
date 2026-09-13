from time import monotonic, time
from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.message
from anyio import Lock, fail_after
from generic_connection_pool.asyncio import ConnectionPool
from loguru import logger
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey

from smartdns.nameservers._dnscrypt import (
    UDP_MINIMUM_SIZE,
    CertInfo,
    StampInfo,
    _tcp_exchange,
    _tcp_roundtrip,
    _udp_roundtrip,
    decrypt_response,
    derive_key,
    encrypt_query,
    fetch_best_cert,
    pad_query,
    parse_stamp,
)
from smartdns.nameservers._pool import (
    HealthCheckedTCPConnectionManager,
    TcpEndpoint,
    TrackedStream,
)
from smartdns.nameservers.base import (
    BaseNameserver,
    query_deadline,
    remaining_timeout,
)

if TYPE_CHECKING:
    from smartdns.models.nameserver import DNSCryptNameserverConfig

# 证书剩余寿命低于该秒数时，查询前触发一次刷新。
CERT_REFRESH_MARGIN = 3600.0
# 上游尚未发布新证书或临时获取失败时，避免每个查询都串行刷新。
CERT_REFRESH_RETRY_INTERVAL = 300.0


class DNSCryptNameserver(BaseNameserver):
    """DNSCrypt 协议 2 上游（XChaCha20-Poly1305，sdns:// stamp 配置）。

    地址、端口、提供者名称与 Ed25519 公钥全部来自 stamp；解析器 X25519
    公钥与 client_magic 在启动时经上游自身端点的明文 TXT 查询获取，
    证书临期或解密失败（上游轮换证书的典型症状）时自动刷新。
    """

    def __init__(self, config: DNSCryptNameserverConfig):
        super().__init__(config)
        self._tcp_only = config.tcp_only
        self._pool_size = config.pool_size
        self._info: StampInfo = parse_stamp(config.stamp)
        self.host = self._info.host
        self.port = self._info.port
        self._cert: CertInfo | None = None
        self._client_pk: bytes | None = None
        self._key: bytes | None = None
        self._cert_generation = 0
        self._next_refresh_attempt = 0.0
        self._pool: ConnectionPool[TcpEndpoint, TrackedStream] | None = None
        # 刷新互斥：同一时刻只有一个查询触发证书重取，其余等待后复用结果。
        self._refresh_lock = Lock()

    def kind(self) -> str:
        return "dnscrypt"

    def is_always_max_size(self) -> bool:
        # UDP 应答 TC 时由 dnspython 以 max_size=True 重调，走 TCP。
        return False

    def answer_nameserver(self) -> str:
        return self.host

    def answer_port(self) -> int:
        return self.port

    async def start(self):
        """启动：获取证书、生成客户端密钥并派生共享密钥。"""
        cert = await fetch_best_cert(
            self.host,
            self.port,
            self._info.provider_name,
            self._info.provider_key,
            self.timeout,
        )
        if cert is None:
            raise ValueError(f"DNSCrypt 上游 {self.name} 未找到有效证书")
        self._install_cert(cert)
        if self._pool_size:
            self._pool = ConnectionPool(
                HealthCheckedTCPConnectionManager(connect_timeout=self.timeout),
                min_idle=1,
                max_size=self._pool_size,
                total_max_size=self._pool_size,
            )
        logger.info(
            "DNSCrypt 上游 {} 已启动，目标: {}:{}，证书 serial={}，TCP 池: {}",
            self.name,
            self.host,
            self.port,
            cert.serial,
            self._pool_size,
        )

    def _install_cert(self, cert: CertInfo) -> None:
        """按新证书重装加密参数；客户端 X25519 密钥对随之更新（会话级，无状态）。"""
        private = PrivateKey.generate()
        self._client_pk = bytes(private.public_key)
        self._key = derive_key(bytes(private), cert.resolver_pk)
        self._cert = cert
        self._cert_generation += 1

    async def _refresh_cert(self, timeout: float | None = None) -> bool:
        """重新获取并安装最佳证书；无有效证书或未变化时返回 False。

        调用方持锁串行化，避免并发查询重复触发证书查询。
        """
        cert = await fetch_best_cert(
            self.host,
            self.port,
            self._info.provider_name,
            self._info.provider_key,
            self.timeout if timeout is None else timeout,
        )
        if cert is None:
            logger.warning("DNSCrypt 上游 {} 证书刷新失败，沿用旧证书", self.name)
            return False
        old_cert = self._cert
        if cert == old_cert:
            return False
        old_serial = old_cert.serial if old_cert is not None else None
        self._install_cert(cert)
        logger.info(
            "DNSCrypt 上游 {} 证书已刷新: serial {} -> {}",
            self.name,
            old_serial,
            cert.serial,
        )
        return True

    async def _ensure_cert_fresh(self, deadline: float) -> None:
        """证书临期时刷新；并发查询经锁合并为一次重取。"""
        cert = self._cert
        if cert is not None and cert.expire - time() > CERT_REFRESH_MARGIN:
            return
        if monotonic() < self._next_refresh_attempt:
            return
        with fail_after(remaining_timeout(deadline)):
            async with self._refresh_lock:
                # 拿到锁后复查：等待期间其他查询可能已完成刷新或设置退避。
                cert = self._cert
                if cert is not None and cert.expire - time() > CERT_REFRESH_MARGIN:
                    return
                if monotonic() < self._next_refresh_attempt:
                    return
                try:
                    await self._refresh_cert(remaining_timeout(deadline))
                finally:
                    self._next_refresh_attempt = (
                        monotonic() + CERT_REFRESH_RETRY_INTERVAL
                    )

    async def stop(self):
        """停止DNSCrypt解析器，关闭 TCP 连接池。"""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        logger.info("DNSCrypt 上游 {} 已停止", self.name)

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        deadline = query_deadline(timeout, self.timeout)
        await self._ensure_cert_fresh(deadline)
        generation = self._cert_generation
        try:
            return await self._exchange(
                request, deadline, max_size, one_rr_per_rrset, ignore_trailing
            )
        except Exception as error:
            # 旧证书参数加密的查询被上游拒绝（解密失败/应答非法）是证书轮换的
            # 典型症状；刷新证书后重试一次，仍失败才向上抛出。
            if not self._is_cert_rotation_error(error):
                raise
            logger.warning(
                "DNSCrypt 上游 {} 疑似证书轮换，刷新后重试: {}",
                self.name,
                error,
            )
            with fail_after(remaining_timeout(deadline)):
                async with self._refresh_lock:
                    # 等锁期间其他请求可能已经安装了新证书；此时直接用新版本重试。
                    if self._cert_generation == generation:
                        refreshed = await self._refresh_cert(
                            remaining_timeout(deadline)
                        )
                        if not refreshed:
                            raise
                    return await self._exchange(
                        request,
                        deadline,
                        max_size,
                        one_rr_per_rrset,
                        ignore_trailing,
                    )

    def _is_cert_rotation_error(self, error: Exception) -> bool:
        """解密/应答校验失败视为证书轮换症状；超时与网络错误不算。"""
        return isinstance(error, (ValueError, CryptoError))

    async def _exchange(
        self,
        request: dns.message.QueryMessage,
        deadline: float,
        max_size: bool,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        if self._cert is None or self._key is None or self._client_pk is None:
            raise ValueError("DNSCrypt解析器未启动")
        use_tcp = self._tcp_only or max_size
        cert = self._cert
        key = self._key
        client_pk = self._client_pk
        assert cert is not None
        assert key is not None
        assert client_pk is not None
        # DNSCrypt 要求加密查询的 DNS ID 为 0（报文头前 2 字节）。
        wire = bytearray(request.to_wire())
        wire[0:2] = b"\x00\x00"
        encrypted, client_nonce = encrypt_query(
            pad_query(bytes(wire), 0 if use_tcp else UDP_MINIMUM_SIZE),
            key,
            client_pk,
            cert.client_magic,
        )
        if use_tcp:
            if self._pool is not None:
                # 连接获取（含新建）与交换共享同一绝对截止时刻。
                endpoint: TcpEndpoint = (self.host, self.port)
                async with self._pool.connection(
                    endpoint, timeout=remaining_timeout(deadline)
                ) as stream:
                    try:
                        response_wire = await _tcp_exchange(
                            stream,
                            encrypted,
                            remaining_timeout(deadline),
                        )
                    except Exception:
                        # 交换中途失败（如超时打断半读应答）后帧对齐不可信，
                        # 标记脏连接，归还池后由健康检查在下次获取时重建。
                        stream.healthy = False
                        raise
            else:
                response_wire = await _tcp_roundtrip(
                    self.host, self.port, encrypted, remaining_timeout(deadline)
                )
        else:
            response_wire = await _udp_roundtrip(
                self.host, self.port, encrypted, remaining_timeout(deadline)
            )
        payload = decrypt_response(response_wire, key, client_nonce)
        response = dns.message.from_wire(
            payload,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=True,
            # UDP 应答带 TC 时抛 Truncated，由 dnspython 以 max_size 重调。
            raise_on_truncation=not use_tcp,
        )
        # 加密应答的 DNS ID 恒为 0，恢复原请求 ID 供调用方核对。
        response.id = request.id
        return response
