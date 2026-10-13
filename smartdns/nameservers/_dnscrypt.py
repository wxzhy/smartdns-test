"""DNSCrypt 协议 2 的 stamp 解析、证书处理与原始传输层。

本模块实现协议 2：响应 magic 为 ``r6fnvWj8``，仅接受 es_version=2
证书。PyNaCl 用于密钥与证书，DNSCrypt 的 XChaCha20 crypto_box 由
libsodium 提供。stamp 通过 dnsstamps 解析。

- 查询以 ``0x80`` 和零字节填充；UDP 明文至少 256 字节，TCP 无下限。
- 应答解密校验 nonce 前 12 字节等于客户端 nonce（回放/错配防护）。

加密交换不经过 dns.asyncquery（其无 dnscrypt 支持），直接用 anyio 套接字
收发；证书经上游自身地址:端口上的普通 DNS TXT 查询获取（规范要求该端点
提供明文证书查询）。
"""

from base64 import urlsafe_b64decode
from dataclasses import dataclass
from ipaddress import ip_address
from re import fullmatch
from struct import pack, unpack
from time import time
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dnsstamps
from anyio import CancelScope, connect_tcp, create_connected_udp_socket, fail_after
from anyio.streams.buffered import BufferedByteReceiveStream
from loguru import logger
from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey
from nacl.utils import random as random_bytes

from smartdns.nameservers._sodium import (
    box_beforenm,
    box_easy_afternm,
    box_open_easy_afternm,
)
from smartdns.nameservers.base import query_deadline, remaining_timeout

if TYPE_CHECKING:
    from anyio.abc import SocketStream

RESOLVER_MAGIC = b"r6fnvWj8"
CERT_MAGIC = b"DNSC"
ES_VERSION_XCHACHA = 2
NONCE_HALF_SIZE = 12
MAC_SIZE = 16
PADDING_BLOCK = 64
UDP_MINIMUM_SIZE = 256
STAMP_PREFIX = "sdns://"
DEFAULT_DNSCRYPT_PORT = 443


@dataclass(slots=True, frozen=True)
class StampInfo:
    """解析后的 sdns:// DNSCrypt stamp。"""

    props: int
    host: str
    port: int
    provider_name: str
    provider_key: bytes  # Ed25519 提供者公钥（32 字节）


@dataclass(slots=True, frozen=True)
class CertInfo:
    """从证书 TXT 中提取的加密参数。"""

    resolver_pk: bytes  # X25519 公钥（32 字节）
    client_magic: bytes  # 8 字节，客户端查询前缀
    serial: int
    expire: int  # 证书过期时刻（Unix 时间戳），供运行期刷新判定


def parse_addr(addr: str) -> tuple[str, int]:
    """解析 stamp 的 addr 字段，返回 (host, port)。

    支持 ``IP:port``、``[IPv6]:port``、无端口的 ``IP``/``[IPv6]``（端口默认
    443），多个地址以 ``;`` 分隔时取第一个。方括号与端口由 urlsplit 解析。
    """
    text = addr.split(";", maxsplit=1)[0]
    if text.startswith("[") and "]" not in text:
        raise ValueError(f"stamp 地址缺少右括号: {addr!r}")
    try:
        parts = urlsplit(f"//{text}")
        host, port = parts.hostname, parts.port
    except ValueError as error:
        raise ValueError(f"stamp 地址或端口非法: {addr!r}") from error
    # urlsplit 把 "IP:"（冒号后为空）视为未写端口，stamp 中按非法处理。
    if text.endswith(":"):
        raise ValueError(f"stamp 端口非法: {addr!r}")
    try:
        ip_address(host or "")
    except ValueError:
        raise ValueError(f"stamp IP 地址非法: {addr!r}") from None
    assert host is not None
    if port is None:
        return host, DEFAULT_DNSCRYPT_PORT
    if not 1 <= port <= 65535:
        raise ValueError(f"stamp 端口越界: {addr!r}")
    return host, port


def parse_stamp(uri: str) -> StampInfo:
    """用 dnsstamps 解析 DNSCrypt stamp，并检查必需字段。"""
    if not uri.startswith(STAMP_PREFIX):
        raise ValueError("stamp 必须以 sdns:// 开头")
    if not fullmatch(r"[A-Za-z0-9_-]+={0,2}", uri[len(STAMP_PREFIX) :]):
        raise ValueError("stamp base64 编码非法")
    try:
        parsed = dnsstamps.parse(uri)
    except Exception as error:
        raise ValueError(f"stamp 解析失败或字段截断: {error}") from error
    if parsed.protocol != dnsstamps.Protocol.DNSCRYPT:
        raise ValueError("stamp 类型不是 DNSCrypt（0x01）")
    try:
        provider_key = bytes.fromhex(parsed.public_key.decode("ascii"))
    except (AttributeError, UnicodeDecodeError, ValueError) as error:
        raise ValueError("stamp 公钥非法或缺失") from error
    if len(provider_key) != 32:
        raise ValueError(f"stamp 公钥长度应为 32 字节，实际 {len(provider_key)}")
    try:
        host, port = parse_addr(parsed.address)
        provider_name = parsed.provider_name
        provider_name.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as error:
        raise ValueError("stamp 地址/提供者名称非法") from error
    if not provider_name:
        raise ValueError("stamp 提供者名称缺失")
    # dnsstamps 1.4.1 会将单个 LP 字段的高位误当作 VLP 续项标志；
    # 用库自身重新编码校验，避免把合法的长提供者名称悄悄截短。
    rebuilt = dnsstamps.build(parsed)[len(STAMP_PREFIX) :]
    original = uri[len(STAMP_PREFIX) :]
    original_bytes = urlsafe_b64decode(original + "=" * (-len(original) % 4))
    rebuilt_bytes = urlsafe_b64decode(rebuilt + "=" * (-len(rebuilt) % 4))
    if original_bytes[9:] != rebuilt_bytes[9:]:
        raise ValueError("stamp 字段解析不完整，当前 dnsstamps 版本不支持此格式")
    options = parsed.options
    props = (
        int(dnsstamps.Option.DNSSEC in options)
        | (int(dnsstamps.Option.NO_LOGS in options) << 1)
        | (int(dnsstamps.Option.NO_FILTERS in options) << 2)
    )
    return StampInfo(
        props=props,
        host=host,
        port=port,
        provider_name=provider_name,
        provider_key=provider_key,
    )


def parse_cert(
    raw: bytes, verify_key: VerifyKey, now: float | None = None
) -> CertInfo | None:
    """解析单个证书 TXT 内容；无效（es1/坏签名/过期等）返回 None。"""
    if len(raw) < 8 + 64 + 52:
        return None
    magic, es_version, _minor, signed = unpack(f"!4sHH{len(raw) - 8}s", raw)
    if magic != CERT_MAGIC:
        logger.warning("DNSCrypt 证书 magic 非法: {}", magic)
        return None
    if es_version != ES_VERSION_XCHACHA:
        logger.warning("跳过非 XChaCha20 证书（es_version={}）", es_version)
        return None
    try:
        body = verify_key.verify(signed)
    except CryptoError:
        logger.warning("DNSCrypt 证书签名校验失败")
        return None
    resolver_pk, client_magic, serial, start, expire = unpack("!32s8sIII", body[:52])
    now = time() if now is None else now
    if start > now:
        logger.warning("DNSCrypt 证书尚未生效: serial={}", serial)
        return None
    if expire < now:
        logger.warning("DNSCrypt 证书已过期: serial={}", serial)
        return None
    return CertInfo(
        resolver_pk=resolver_pk,
        client_magic=client_magic,
        serial=serial,
        expire=expire,
    )


def pad_query(wire: bytes, minimum: int) -> bytes:
    """按规范填充查询明文：总量 64 字节对齐、UDP 下至少 256 字节。

    填充为一个 ``0x80`` 字节后跟零；即使已对齐也至少追加 1 字节。
    """
    target = max(len(wire) + 1, minimum)
    target = -(-target // PADDING_BLOCK) * PADDING_BLOCK
    return wire + b"\x80" + b"\x00" * (target - len(wire) - 1)


def derive_key(client_private: bytes, resolver_pk: bytes) -> bytes:
    """X25519 + HChaCha20 派生 DNSCrypt v2 crypto_box 共享密钥。"""
    return box_beforenm(client_private, resolver_pk)


def encrypt_query(
    wire: bytes, key: bytes, client_pk: bytes, client_magic: bytes
) -> tuple[bytes, bytes]:
    """加密查询：nonce 为 12 随机字节 + 12 零字节。

    返回 (查询 wire, 客户端 nonce)；wire 布局为
    ``client_magic(8) | client_pk(32) | client_nonce(12) | ciphertext+mac``。
    """
    nonce = random_bytes(NONCE_HALF_SIZE)
    ciphertext = box_easy_afternm(wire, nonce + b"\x00" * NONCE_HALF_SIZE, key)
    return client_magic + client_pk + nonce + ciphertext, nonce


def decrypt_response(wire: bytes, key: bytes, client_nonce: bytes) -> bytes:
    """解密协议 2 应答，返回 DNS 报文明文（含可能的填充）。"""
    if len(wire) < 8 + NONCE_HALF_SIZE * 2 + MAC_SIZE:
        raise ValueError("DNSCrypt 应答过短")
    magic, nonce, ciphertext = unpack(
        f"!8s{NONCE_HALF_SIZE * 2}s{len(wire) - 32}s", wire
    )
    if magic != RESOLVER_MAGIC:
        raise ValueError("应答不是 DNSCrypt 协议 2 应答")
    if nonce[:NONCE_HALF_SIZE] != client_nonce:
        raise ValueError("应答 nonce 与请求不匹配")
    return box_open_easy_afternm(ciphertext, nonce, key)


def unpad_response(wire: bytes) -> bytes:
    """Strip mandatory ISO/IEC 7816-4 padding from an authenticated response."""
    end = len(wire) - 1
    while end >= 0 and wire[end] == 0:
        end -= 1
    if end < 0 or wire[end] != 0x80:
        raise ValueError("DNSCrypt 应答填充非法")
    return wire[:end]


async def _tcp_exchange(stream: SocketStream, wire: bytes, timeout: float) -> bytes:
    """在既有 TCP 流上完成 2 字节长度前缀分帧交换，返回应答 wire。"""
    with fail_after(timeout):
        await stream.send(pack("!H", len(wire)) + wire)
        reader = BufferedByteReceiveStream(stream)
        (length,) = unpack("!H", await reader.receive_exactly(2))
        return await reader.receive_exactly(length)


async def _tcp_roundtrip(host: str, port: int, wire: bytes, timeout: float) -> bytes:
    """TCP 交换：新建连接、用后关闭（证书获取与无池路径使用）。"""
    deadline = query_deadline(timeout, timeout)
    with fail_after(remaining_timeout(deadline)):
        stream = await connect_tcp(host, port)
    try:
        return await _tcp_exchange(stream, wire, remaining_timeout(deadline))
    finally:
        with CancelScope(shield=True):
            await stream.aclose()


async def _udp_roundtrip(host: str, port: int, wire: bytes, timeout: float) -> bytes:
    """UDP 交换：connected 套接字单发单收，返回单个应答数据报。"""
    with fail_after(timeout):
        async with await create_connected_udp_socket(host, port) as sock:
            await sock.send(wire)
            # 数据报接口的 receive() 不带长度参数，返回整个数据报。
            return await sock.receive()


async def fetch_certs(
    host: str, port: int, provider_name: str, timeout: float
) -> list[bytes]:
    """向上游自身发起普通 TXT 查询获取证书内容；UDP 失败或 TC 后回退 TCP。"""
    deadline = query_deadline(timeout, timeout)
    query = dns.message.make_query(provider_name, dns.rdatatype.TXT)
    try:
        # UDP 黑洞不能耗尽全部预算，否则规范要求的 TCP 回退永远没有机会执行。
        udp_timeout = remaining_timeout(deadline) / 2
        response = await _udp_roundtrip(host, port, query.to_wire(), udp_timeout)
        message = dns.message.from_wire(response)
        if not query.is_response(message) or message.question != query.question:
            raise dns.query.BadResponse("DNSCrypt 证书应答与查询不匹配")
        if message.rcode() == dns.rcode.NOERROR and not message.flags & dns.flags.TC:
            return _cert_payloads(message)
    except Exception:
        # 超时、应答截断或收到非法报文：统一回退 TCP。
        logger.info("DNSCrypt 证书 UDP 获取失败，回退 TCP: {}", provider_name)
    response = await _tcp_roundtrip(
        host, port, query.to_wire(), remaining_timeout(deadline)
    )
    message = dns.message.from_wire(response)
    if not query.is_response(message) or message.question != query.question:
        raise dns.query.BadResponse("DNSCrypt 证书应答与查询不匹配")
    return _cert_payloads(message)


async def fetch_best_cert(
    host: str,
    port: int,
    provider_name: str,
    provider_key: bytes,
    timeout: float,
) -> CertInfo | None:
    """获取证书并挑选 serial 最大的有效 es2 证书；无有效证书返回 None。"""
    verify_key = VerifyKey(provider_key)
    best: CertInfo | None = None
    for payload in await fetch_certs(host, port, provider_name, timeout):
        cert = parse_cert(payload, verify_key)
        if cert is not None and (best is None or cert.serial > best.serial):
            best = cert
    return best


def _cert_payloads(message: dns.message.Message) -> list[bytes]:
    """把 TXT 应答中每个 RR 的全部字符串拼接为证书原始字节。"""
    return [b"".join(rr.strings) for rrset in message.answer for rr in rrset]
