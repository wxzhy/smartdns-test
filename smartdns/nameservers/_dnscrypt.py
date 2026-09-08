"""DNSCrypt 协议 2 的 stamp 解析、证书处理与原始传输层。

参考 utils/dnscrypt-python.py（v1 参考实现），本模块只实现当前通用的
协议 2：响应 magic 为 ``r6fnvWjl``，仅接受 es_version=2 证书（X25519
共享密钥 + XChaCha20-Poly1305 AEAD，经 PyNaCl）。与参考实现的已知偏差：

- 填充按规范实现（UDP 明文至少 256 字节、总量 64 字节对齐，``0x80`` +
  零填充；TCP 仅 64 字节对齐无下限）——参考实现的填充不合规。
- 应答解密校验 nonce 前 12 字节等于客户端 nonce（回放/错配防护）。

加密交换不经过 dns.asyncquery（其无 dnscrypt 支持），直接用 anyio 套接字
收发；证书经上游自身地址:端口上的普通 DNS TXT 查询获取（规范要求该端点
提供明文证书查询）。
"""

from base64 import urlsafe_b64decode
from dataclasses import dataclass
from struct import pack, unpack
from time import monotonic, time

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
from anyio import connect_tcp, create_connected_udp_socket, fail_after
from loguru import logger
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
)
from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey
from nacl.utils import random as random_bytes

RESOLVER_MAGIC = b"r6fnvWjl"
CERT_MAGIC = b"DNSC"
ES_VERSION_XCHACHA = 2
NONCE_HALF_SIZE = 12
MAC_SIZE = 16
PADDING_BLOCK = 64
UDP_MINIMUM_SIZE = 256
STAMP_PREFIX = "sdns://"
STAMP_TYPE_DNSCRYPT = 0x01
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


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """读取 LEB128 无符号 varint，返回 (值, 新偏移)。"""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("stamp 数据在字段中间截断")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            raise ValueError("stamp varint 长度异常")


def _read_bytes(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    if offset + length > len(data):
        raise ValueError("stamp 数据在字段中间截断")
    return data[offset : offset + length], offset + length


def parse_addr(addr: str) -> tuple[str, int]:
    """解析 stamp 的 addr 字段，返回 (host, port)。

    支持 ``IP:port``、``[IPv6]:port``、无端口的 ``IP``/``[IPv6]``（端口默认
    443），多个地址以 ``;`` 分隔时取第一个。
    """
    text = addr.split(";", maxsplit=1)[0]
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep:
            raise ValueError(f"stamp 地址缺少右括号: {addr!r}")
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep:
            host, port_text = text, ""
    if not port_text:
        return host, DEFAULT_DNSCRYPT_PORT
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"stamp 端口非法: {addr!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"stamp 端口越界: {addr!r}")
    return host, port


def parse_stamp(uri: str) -> StampInfo:
    """解析 sdns:// DNSCrypt stamp（类型字节 0x01）。

    布局：``0x01 | props(8 字节 LE uint64) | varint(addr) | varint(pk=32)
    | varint(providerName)``；addr 可省略端口（默认 443）。
    """
    if not uri.startswith(STAMP_PREFIX):
        raise ValueError("stamp 必须以 sdns:// 开头")
    encoded = uri[len(STAMP_PREFIX) :]
    try:
        data = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as error:
        raise ValueError(f"stamp base64 解码失败: {error}") from None
    if len(data) < 9 or data[0] != STAMP_TYPE_DNSCRYPT:
        raise ValueError("stamp 类型不是 DNSCrypt（0x01）")
    props = int.from_bytes(data[1:9], "little")
    offset = 9
    addr_len, offset = _read_varint(data, offset)
    addr_raw, offset = _read_bytes(data, offset, addr_len)
    pk_len, offset = _read_varint(data, offset)
    if pk_len != 32:
        raise ValueError(f"stamp 公钥长度应为 32 字节，实际 {pk_len}")
    pk_raw, offset = _read_bytes(data, offset, pk_len)
    name_len, offset = _read_varint(data, offset)
    name_raw, _ = _read_bytes(data, offset, name_len)
    try:
        host, port = parse_addr(addr_raw.decode("ascii"))
        provider_name = name_raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("stamp 地址/提供者名称非 ASCII") from None
    return StampInfo(
        props=props,
        host=host,
        port=port,
        provider_name=provider_name,
        provider_key=pk_raw,
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
    """X25519 共享密钥（crypto_box_beforenm 等价），供 XChaCha20 直接使用。"""
    return crypto_scalarmult(client_private, resolver_pk)


def encrypt_query(
    wire: bytes, key: bytes, client_pk: bytes, client_magic: bytes
) -> tuple[bytes, bytes]:
    """加密查询：nonce 为 12 随机字节 + 12 零字节。

    返回 (查询 wire, 客户端 nonce)；wire 布局为
    ``client_magic(8) | client_pk(32) | client_nonce(12) | ciphertext+mac``。
    """
    nonce = random_bytes(NONCE_HALF_SIZE)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        wire, None, nonce + b"\x00" * NONCE_HALF_SIZE, key
    )
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
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)


async def _receive_exact(stream, size: int) -> bytes:
    """从 anyio 流中精确读取 size 字节。"""
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunks.append(await stream.receive(remaining))
        remaining -= len(chunks[-1])
    return b"".join(chunks)


async def _tcp_exchange(stream, wire: bytes, timeout: float) -> bytes:
    """在既有 TCP 流上完成 2 字节分帧交换，返回应答 wire。"""
    with fail_after(timeout):
        await stream.send(pack("!H", len(wire)) + wire)
        (length,) = unpack("!H", await _receive_exact(stream, 2))
        return await _receive_exact(stream, length)


async def _tcp_roundtrip(host: str, port: int, wire: bytes, timeout: float) -> bytes:
    """TCP 交换：新建连接、用后关闭（证书获取与无池路径使用）。"""
    deadline = monotonic() + timeout
    with fail_after(timeout):
        stream = await connect_tcp(host, port)
    try:
        return await _tcp_exchange(stream, wire, max(deadline - monotonic(), 0.1))
    finally:
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
    query = dns.message.make_query(provider_name, dns.rdatatype.TXT)
    try:
        response = await _udp_roundtrip(host, port, query.to_wire(), timeout)
        message = dns.message.from_wire(response)
        if message.rcode() == dns.rcode.NOERROR and not message.flags & dns.flags.TC:
            return _cert_payloads(message)
    except Exception:
        # 超时、应答截断或收到非法报文：统一回退 TCP。
        logger.info("DNSCrypt 证书 UDP 获取失败，回退 TCP: {}", provider_name)
    response = await _tcp_roundtrip(host, port, query.to_wire(), timeout)
    return _cert_payloads(dns.message.from_wire(response))


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
