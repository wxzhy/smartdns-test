from time import monotonic
from typing import TYPE_CHECKING

import dns.asyncbackend
import dns.message
from generic_connection_pool.asyncio import ConnectionPool
from loguru import logger
from nacl.public import PrivateKey
from nacl.signing import VerifyKey

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
    fetch_certs,
    pad_query,
    parse_cert,
    parse_stamp,
)
from smartdns.nameservers._pool import (
    HealthCheckedTCPConnectionManager,
    TcpEndpoint,
    TrackedStream,
)
from smartdns.nameservers.base import BaseNameserver

if TYPE_CHECKING:
    from smartdns.models.nameserver import DNSCryptNameserverConfig


class DNSCryptNameserver(BaseNameserver):
    """DNSCrypt 协议 2 上游（XChaCha20-Poly1305，sdns:// stamp 配置）。

    地址、端口、提供者名称与 Ed25519 公钥全部来自 stamp；解析器 X25519
    公钥与 client_magic 在启动时经上游自身端点的明文 TXT 查询获取。
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
        self._pool: ConnectionPool[TcpEndpoint, TrackedStream] | None = None

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
        verify_key = VerifyKey(self._info.provider_key)
        payloads = await fetch_certs(
            self.host, self.port, self._info.provider_name, self.timeout
        )
        best: CertInfo | None = None
        for payload in payloads:
            cert = parse_cert(payload, verify_key)
            if cert is not None and (best is None or cert.serial > best.serial):
                best = cert
        if best is None:
            raise ValueError(f"DNSCrypt 上游 {self.name} 未找到有效证书")
        self._cert = best
        private = PrivateKey.generate()
        self._client_pk = bytes(private.public_key)
        self._key = derive_key(bytes(private), best.resolver_pk)
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
            best.serial,
            self._pool_size,
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
        if self._cert is None or self._key is None or self._client_pk is None:
            raise ValueError("DNSCrypt解析器未启动")
        # 传入 timeout 为剩余 lifetime；0/None（未设置或已到期）回退到完整配置超时。
        effective_timeout = (
            timeout if timeout is not None and timeout > 0 else self.timeout
        )
        try:
            use_tcp = self._tcp_only or max_size
            # DNSCrypt 要求加密查询的 DNS ID 为 0（报文头前 2 字节）。
            wire = bytearray(request.to_wire())
            wire[0:2] = b"\x00\x00"
            encrypted, client_nonce = encrypt_query(
                pad_query(bytes(wire), 0 if use_tcp else UDP_MINIMUM_SIZE),
                self._key,
                self._client_pk,
                self._cert.client_magic,
            )
            if use_tcp:
                if self._pool is not None:
                    # 连接获取（含新建）计入总时限；0.1 与配置最小超时一致。
                    endpoint: TcpEndpoint = (self.host, self.port)
                    deadline = monotonic() + effective_timeout
                    async with self._pool.connection(
                        endpoint, timeout=effective_timeout
                    ) as stream:
                        try:
                            response_wire = await _tcp_exchange(
                                stream,
                                encrypted,
                                max(deadline - monotonic(), 0.1),
                            )
                        except Exception:
                            # 交换中途失败（如超时打断半读应答）后帧对齐不可信，
                            # 标记脏连接，归还池后由健康检查在下次获取时重建。
                            stream.healthy = False
                            raise
                else:
                    response_wire = await _tcp_roundtrip(
                        self.host, self.port, encrypted, effective_timeout
                    )
            else:
                response_wire = await _udp_roundtrip(
                    self.host, self.port, encrypted, effective_timeout
                )
            payload = decrypt_response(response_wire, self._key, client_nonce)
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
        except Exception:
            logger.warning("DNSCrypt 上游 {} 查询失败", self.name)
            raise
