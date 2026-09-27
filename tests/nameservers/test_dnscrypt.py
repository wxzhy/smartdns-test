"""DNSCrypt 协议 2 nameserver 测试。

进程内假服务器（Ed25519 签发 es2 证书 + X25519 + XChaCha20 加解密）同时
服务普通 DNS（证书 TXT 查询）与加密 DNSCrypt 查询，覆盖 stamp 解析、证书
选择、UDP/TCP 端到端、TC 截断与回放防护。
"""

import asyncio
import struct
from base64 import urlsafe_b64encode
from contextlib import suppress
from time import time
from typing import TYPE_CHECKING, cast

import dns.asyncbackend
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dnsstamps
import pytest
from dns.rdtypes.ANY.TXT import TXT
from nacl.bindings import crypto_scalarmult_base
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from nacl.utils import random as random_bytes

import smartdns.nameservers.dnscrypt as dnscrypt_module
from smartdns.models.nameserver import DNSCryptNameserverConfig
from smartdns.nameservers._dnscrypt import (
    RESOLVER_MAGIC,
    decrypt_response,
    derive_key,
    encrypt_query,
    pad_query,
    parse_addr,
    parse_stamp,
    unpad_response,
)
from smartdns.nameservers._sodium import (
    box_beforenm,
    box_easy_afternm,
    box_open_easy_afternm,
)
from smartdns.nameservers.dnscrypt import DNSCryptNameserver
from smartdns.nameservers.manager import NameserverManager

if TYPE_CHECKING:
    from smartdns.nameservers.client import HTTPClient

CLIENT_MAGIC = b"CLMAG321"
PADDED_ANSWER_IP = "192.0.2.1"


class _FakeDnsCryptServer:
    """进程内 DNSCrypt 协议 2 服务器，UDP/TCP 复用同一套报文处理。"""

    def __init__(self) -> None:
        self.signing_key = SigningKey.generate()
        self.provider_key = bytes(self.signing_key.verify_key.encode())
        self.provider_name = "2.dnscrypt-cert.example.test"
        self.server_private = PrivateKey.generate()
        self.client_magic = CLIENT_MAGIC
        self.force_tc = False
        self.wrong_id = False
        self.wrong_question = False
        # (es_version, serial, start_offset, expire_offset, break_signature)
        self.certs: list[tuple[int, int, int, int, bool]] = [(2, 2, -100, 86400, False)]
        self.transport_counts = {"udp": 0, "tcp": 0}
        self.tcp_connections = 0

    def build_cert(
        self,
        es_version: int = 2,
        serial: int = 2,
        start_offset: int = -100,
        expire_offset: int = 86400,
        break_signature: bool = False,
    ) -> bytes:
        body = (
            bytes(self.server_private.public_key)
            + self.client_magic
            + struct.pack(
                "!III", serial, int(time()) + start_offset, int(time()) + expire_offset
            )
        )
        tampered = b"tampered" if break_signature else body
        signature = self.signing_key.sign(tampered).signature
        return struct.pack("!4sHH", b"DNSC", es_version, 0) + signature + body

    def handle_wire(self, data: bytes, transport: str) -> bytes:
        self.transport_counts[transport] += 1
        try:
            return self._handle_dnscrypt(data)
        except Exception:
            return self._handle_plain(data)

    def _handle_dnscrypt(self, data: bytes) -> bytes:
        if data[:8] != self.client_magic:
            raise ValueError("不是 DNSCrypt 查询")
        client_pk = data[8:40]
        client_nonce = data[40:52]
        shared = box_beforenm(bytes(self.server_private.encode()), client_pk)
        payload = box_open_easy_afternm(data[52:], client_nonce + b"\x00" * 12, shared)
        query = dns.message.from_wire(unpad_response(payload))
        response = dns.message.make_response(query)
        if self.wrong_id:
            response.id ^= 1
        if self.wrong_question:
            response.question = dns.message.make_query("other.example.", "A").question
        # str(Name) 渲染为带根点的绝对域名，构造 rrset 需要绝对名。
        response.answer.append(
            dns.rrset.from_text(
                str(query.question[0].name), 60, "IN", "A", PADDED_ANSWER_IP
            )
        )
        if self.force_tc:
            response.flags |= dns.flags.TC
        response_wire = pad_query(response.to_wire(), 0)
        combined = client_nonce + random_bytes(12)
        ciphertext = box_easy_afternm(response_wire, combined, shared)
        return RESOLVER_MAGIC + combined + ciphertext

    def _handle_plain(self, data: bytes) -> bytes:
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        for es_version, serial, start, expire, broken in self.certs:
            cert = self.build_cert(
                es_version=es_version,
                serial=serial,
                start_offset=start,
                expire_offset=expire,
                break_signature=broken,
            )
            rr = TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [cert])
            response.answer.append(
                dns.rrset.from_rdata(self.provider_name + ".", 60, rr)
            )
        return response.to_wire()


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _stamp(host: str, port: int, server: _FakeDnsCryptServer) -> str:
    return dnsstamps.create_dnscrypt(
        f"{host}:{port}",
        server.provider_key.hex(),
        server.provider_name,
        options=[
            dnsstamps.Option.DNSSEC,
            dnsstamps.Option.NO_LOGS,
            dnsstamps.Option.NO_FILTERS,
        ],
    )


async def _start_udp(
    server: _FakeDnsCryptServer,
) -> tuple[asyncio.DatagramTransport, int]:
    class _Proto(asyncio.DatagramProtocol):
        def connection_made(self, transport) -> None:
            self.transport = transport

        def datagram_received(self, data, addr) -> None:
            with suppress(Exception):
                self.transport.sendto(server.handle_wire(data, "udp"), addr)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _Proto, local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    return transport, port


async def _start_tcp(
    server: _FakeDnsCryptServer, port: int | None = None
) -> tuple[asyncio.AbstractServer, int]:
    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        server.tcp_connections += 1  # 每个被接受的 TCP 连接进入一次 handle
        try:
            while True:
                (length,) = struct.unpack("!H", await reader.readexactly(2))
                payload = await reader.readexactly(length)
                resp = server.handle_wire(payload, "tcp")
                writer.write(struct.pack("!H", len(resp)) + resp)
                await writer.drain()
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        finally:
            writer.close()

    # DNSCrypt 上游的 UDP 与 TCP 同端口；未指定端口时取临时端口。
    bind_port = port if port is not None else 0
    tcp = await asyncio.start_server(handle, "127.0.0.1", bind_port)
    actual = tcp.sockets[0].getsockname()[1]
    return tcp, actual


async def _make_nameserver(
    server: _FakeDnsCryptServer,
    port: int,
    *,
    tcp_only: bool = False,
    pool_size: int = 0,
) -> DNSCryptNameserver:
    config = DNSCryptNameserverConfig(
        name="dc",
        type="dnscrypt",
        stamp=_stamp("127.0.0.1", port, server),
        tcp_only=tcp_only,
        pool_size=pool_size,
    )
    nameserver = DNSCryptNameserver(config)
    await nameserver.start()
    return nameserver


async def _query(nameserver: DNSCryptNameserver, *, max_size: bool = False):
    request = dns.message.make_query("example.com.", "A")
    return await nameserver.async_query(
        request,
        timeout=2.0,
        source=None,
        source_port=0,
        max_size=max_size,
        backend=cast("dns.asyncbackend.Backend", object()),
    )


def test_parse_stamp_extracts_fields() -> None:
    server = _FakeDnsCryptServer()
    info = parse_stamp(_stamp("9.9.9.10", 8443, server))
    assert info.host == "9.9.9.10"
    assert info.port == 8443
    assert info.provider_name == server.provider_name
    assert info.provider_key == server.provider_key
    assert info.props == 7


def test_parse_real_stamp() -> None:
    # 来自 dnscrypt 公共解析器列表的真实 stamp（cryptostorm 维也纳）。
    info = parse_stamp(
        "sdns://AQcAAAAAAAAADTk0LjE5OC40MS4yMzUgMTNyrVlWMsJBa4cvCY-FG925ZS"
        "hMbL6aTxkJZDDbqVoeMi5kbnNjcnlwdC1jZXJ0LmNyeXB0b3N0b3JtLmlz"
    )
    assert info.host == "94.198.41.235"
    assert info.port == 443  # addr 省略端口时默认 443
    assert info.provider_name == "2.dnscrypt-cert.cryptostorm.is"
    assert len(info.provider_key) == 32
    assert info.props == 7


def test_parse_addr_variants() -> None:
    assert parse_addr("1.2.3.4:443") == ("1.2.3.4", 443)
    assert parse_addr("[2001:db8::1]:5353") == ("2001:db8::1", 5353)
    # 省略端口时默认 443。
    assert parse_addr("1.2.3.4") == ("1.2.3.4", 443)
    assert parse_addr("[2001:db8::1]") == ("2001:db8::1", 443)
    # 多地址取第一个。
    assert parse_addr("1.2.3.4:44;5.6.7.8:53") == ("1.2.3.4", 44)
    with pytest.raises(ValueError, match="端口"):
        parse_addr("1.2.3.4:99999")
    with pytest.raises(ValueError, match="右括号"):
        parse_addr("[2001:db8::1")


def test_parse_stamp_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="sdns://"):
        parse_stamp("https://example.com")
    with pytest.raises(ValueError, match="base64"):
        parse_stamp("sdns://!!!not-base64!!!")
    with pytest.raises(ValueError, match="类型"):
        parse_stamp(dnsstamps.create_plain("1.2.3.4"))
    with pytest.raises(ValueError, match="截断"):
        # 类型 + props 正常，addr 长度声明 16 字节但数据缺失。
        parse_stamp(
            "sdns://"
            + urlsafe_b64encode(b"\x01" + b"\x00" * 8 + b"\x10").rstrip(b"=").decode()
        )
    payload = b"\x01" + b"\x00" * 8 + _varint(7) + b"1.2.3.4" + _varint(3) + b"abc"
    with pytest.raises(ValueError, match="公钥"):
        parse_stamp("sdns://" + urlsafe_b64encode(payload).rstrip(b"=").decode())


def test_parse_stamp_does_not_silently_truncate_long_provider_name() -> None:
    provider_name = "2.dnscrypt-cert." + "a" * 60 + "." + "b" * 56
    assert len(provider_name) == 133
    stamp = dnsstamps.create_dnscrypt("9.9.9.9", "ff" * 32, provider_name)
    with pytest.raises(ValueError, match="字段解析不完整"):
        parse_stamp(stamp)


def test_pad_query_spec_alignment() -> None:
    # UDP：总量 64 对齐且至少 256 字节，0x80 开头的填充。
    padded = pad_query(b"x" * 10, 256)
    assert len(padded) == 256
    assert len(padded) % 64 == 0
    assert padded[10:] == b"\x80" + b"\x00" * 245
    # 已对齐时仍至少追加 1 字节。
    aligned = pad_query(b"x" * 256, 256)
    assert len(aligned) == 320
    # TCP：无最小长度，仅 64 对齐。
    assert len(pad_query(b"x" * 10, 0)) == 64


def test_replay_guard_rejects_nonce_mismatch() -> None:
    key = derive_key(
        PrivateKey.generate().encode(), PrivateKey.generate().public_key.encode()
    )
    encrypted, nonce = encrypt_query(b"q", key, b"k" * 32, CLIENT_MAGIC)
    # 应答 nonce 前 12 字节必须等于客户端 nonce，否则拒绝。
    wire = RESOLVER_MAGIC + b"\xff" * 12 + nonce + encrypted[52:]
    with pytest.raises(ValueError, match="nonce"):
        decrypt_response(wire, key, nonce)


def test_official_dnscrypt_v2_crypto_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    # https://dnscrypt.github.io/dnscrypt-protocol/draft-denis-dprive-dnscrypt.html#appendix-2-dnscrypt-test-vectors
    resolver_pk = bytes.fromhex(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    )
    client_sk = bytes(range(0x40, 0x60))
    client_pk = crypto_scalarmult_base(client_sk)
    assert client_pk.hex() == (
        "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
    )
    key = derive_key(client_sk, resolver_pk)
    assert key.hex() == (
        "335d32f2d65e6623cbbd05b6539c9575fee16cb5405fe839ab4bd291fdf13262"
    )
    monkeypatch.setattr(
        "smartdns.nameservers._dnscrypt.random_bytes",
        lambda count: bytes(range(0xA0, 0xA0 + count)),
    )
    query = bytes.fromhex(
        "12340100000100000000000003777777076578616d706c6503636f6d0000010001"
    )
    wire, nonce = encrypt_query(
        pad_query(query, 256), key, client_pk, bytes.fromhex("b1b2b3b4b5b6b7b8")
    )
    assert len(wire) == 324
    assert wire[52:68].hex() == "2dae527c26386d5cd4e61152db6dd181"
    assert wire[68:100].hex() == (
        "2ff6aaf7644fc122afc70b1b580b18f10fbc26577abc759152cde31cd0afc5c5"
    )
    response_wire = bytes.fromhex(
        "7236666e76576a38a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb"
        "f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87"
        "41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6"
        "cc22cc13e829d2e51d1c00ea64d1d39d"
    )
    assert unpad_response(decrypt_response(response_wire, key, nonce)).hex() == (
        "12348180000100010000000003777777076578616d706c6503636f6d0000010001"
        "c00c0001000100000e1000045db8d822"
    )


async def test_udp_query_round_trip() -> None:
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        response = await _query(nameserver)
        assert response.rcode() == dns.rcode.NOERROR
        assert response.answer[0][0].address == PADDED_ANSWER_IP
        assert server.transport_counts == {"udp": 2, "tcp": 0}  # 证书 + 查询
        await nameserver.stop()
    finally:
        transport.close()


async def test_tcp_only_round_trip_with_udp_fallback_cert() -> None:
    # 只有 TCP 服务器：证书获取走 UDP 失败后回退 TCP，查询全走 TCP。
    server = _FakeDnsCryptServer()
    tcp, port = await _start_tcp(server)
    try:
        nameserver = await _make_nameserver(server, port, tcp_only=True)
        response = await _query(nameserver)
        assert response.answer[0][0].address == PADDED_ANSWER_IP
        assert server.transport_counts["tcp"] >= 2  # 证书回退 + 查询
        await nameserver.stop()
    finally:
        tcp.close()


async def test_max_size_goes_tcp() -> None:
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    tcp, _ = await _start_tcp(server, port)  # TCP 与 UDP 同端口，与真实上游一致
    try:
        nameserver = await _make_nameserver(server, port)
        await _query(nameserver, max_size=True)
        assert server.transport_counts["udp"] == 1  # 仅证书获取走 UDP
        assert server.transport_counts["tcp"] == 1
        await nameserver.stop()
    finally:
        transport.close()
        tcp.close()


async def test_truncated_udp_raises() -> None:
    server = _FakeDnsCryptServer()
    server.force_tc = True
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        with pytest.raises(dns.message.Truncated):
            await _query(nameserver)
        await nameserver.stop()
    finally:
        transport.close()


@pytest.mark.parametrize("fault", ["wrong_id", "wrong_question"])
async def test_rejects_mismatched_encrypted_response(fault: str) -> None:
    server = _FakeDnsCryptServer()
    setattr(server, fault, True)
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        with pytest.raises(dns.query.BadResponse):
            await _query(nameserver)
        await nameserver.stop()
    finally:
        transport.close()


async def test_cert_selection_prefers_highest_serial() -> None:
    server = _FakeDnsCryptServer()
    server.certs = [(2, 1, -100, 86400, False), (2, 7, -100, 86400, False)]
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        assert nameserver._cert.serial == 7
        await nameserver.stop()
    finally:
        transport.close()


async def test_start_skips_es1_expired_and_broken_certs() -> None:
    server = _FakeDnsCryptServer()
    server.certs = [
        (1, 9, -100, 86400, False),  # es1：跳过
        (2, 8, -86400 * 30, -1, False),  # 已过期：跳过
        (2, 6, -100, 86400, True),  # 坏签名：跳过
        (2, 3, -100, 86400, False),  # 唯一有效
    ]
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        assert nameserver._cert.serial == 3
        await nameserver.stop()
    finally:
        transport.close()


async def test_start_raises_without_valid_cert() -> None:
    server = _FakeDnsCryptServer()
    server.certs = [(1, 1, -100, 86400, False)]  # 只有 es1 证书
    transport, port = await _start_udp(server)
    try:
        with pytest.raises(ValueError, match="未找到有效证书"):
            await _make_nameserver(server, port)
    finally:
        transport.close()


async def test_tcp_pool_setting_still_uses_one_connection_per_query() -> None:
    # DNSCrypt 协议每条 TCP 连接只能进行一次加密查询，即使配置旧的 pool_size。
    server = _FakeDnsCryptServer()
    tcp, port = await _start_tcp(server)
    try:
        nameserver = await _make_nameserver(server, port, tcp_only=True, pool_size=1)
        for _ in range(3):
            response = await _query(nameserver)
            assert response.answer[0][0].address == PADDED_ANSWER_IP
        # 1 条证书回退连接 + 3 条查询连接。
        assert server.tcp_connections == 4
        assert server.transport_counts["tcp"] == 4  # 证书 + 3 次查询
        await nameserver.stop()
    finally:
        tcp.close()


async def test_tcp_without_pool_makes_new_connections() -> None:
    # pool_size=0：每次查询新建连接。
    server = _FakeDnsCryptServer()
    tcp, port = await _start_tcp(server)
    try:
        nameserver = await _make_nameserver(server, port, tcp_only=True)
        for _ in range(2):
            await _query(nameserver)
        # 1 条证书回退临时连接 + 每次查询各 1 条。
        assert server.tcp_connections == 3
        assert server.transport_counts["tcp"] == 3
        await nameserver.stop()
    finally:
        tcp.close()


async def test_manager_registers_dnscrypt() -> None:
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        config = DNSCryptNameserverConfig(
            name="dc",
            type="dnscrypt",
            stamp=_stamp("127.0.0.1", port, server),
        )
        manager = NameserverManager([config], cast("HTTPClient", None))
        await manager.start_all()
        try:
            nameserver = manager.get("dc")
            assert isinstance(nameserver, DNSCryptNameserver)
            assert nameserver.kind() == "dnscrypt"
            assert nameserver.answer_nameserver() == "127.0.0.1"
            assert nameserver.answer_port() == port
        finally:
            await manager.stop_all()
    finally:
        transport.close()


async def test_cert_rotation_triggers_refresh_and_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上游轮换证书后旧参数解密失败（MAC 校验不通过），应刷新证书并重试成功。"""
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        old_serial = nameserver._cert.serial
        # 服务端发布新证书（新 serial）；本地仍用旧证书参数，首轮解密失败。
        server.certs = [(2, old_serial + 1, -100, 86400, False)]
        real_decrypt = dnscrypt_module.decrypt_response
        first_attempt = True

        def flaky_decrypt(wire, key, client_nonce):
            nonlocal first_attempt
            if first_attempt:
                first_attempt = False
                raise CryptoError("MAC 校验失败：上游已用新证书应答")
            return real_decrypt(wire, key, client_nonce)

        monkeypatch.setattr(dnscrypt_module, "decrypt_response", flaky_decrypt)

        response = await _query(nameserver)
        assert response.answer[0][0].address == PADDED_ANSWER_IP
        assert nameserver._cert is not None
        assert nameserver._cert.serial == old_serial + 1
        await nameserver.stop()
    finally:
        transport.close()


async def test_concurrent_rotation_errors_reuse_single_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """并发旧证书请求同时失败时，应都使用首个请求刷新的证书重试。"""
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        old_serial = nameserver._cert.serial
        server.certs = [(2, old_serial + 1, -100, 86400, False)]
        original_exchange = nameserver._exchange
        attempts: dict[int, int] = {}
        first_attempts = 0
        both_started = asyncio.Event()

        async def controlled_exchange(request, *args, **kwargs):
            nonlocal first_attempts
            key = id(request)
            attempts[key] = attempts.get(key, 0) + 1
            if attempts[key] == 1:
                first_attempts += 1
                if first_attempts == 2:
                    both_started.set()
                await both_started.wait()
                raise CryptoError("旧证书交换失败")
            return await original_exchange(request, *args, **kwargs)

        monkeypatch.setattr(nameserver, "_exchange", controlled_exchange)
        responses = await asyncio.gather(_query(nameserver), _query(nameserver))

        assert all(
            response.answer[0][0].address == PADDED_ANSWER_IP for response in responses
        )
        assert nameserver._cert.serial == old_serial + 1
        assert sorted(attempts.values()) == [2, 2]
        await nameserver.stop()
    finally:
        transport.close()


async def test_unchanged_expiring_cert_refresh_is_backed_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """临期证书未更新时，在退避期内不应每次查询都重新取证书。"""
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        object.__setattr__(nameserver._cert, "expire", int(time()) + 60)
        refreshes = 0

        async def unchanged_refresh(timeout=None) -> bool:
            nonlocal refreshes
            refreshes += 1
            return False

        monkeypatch.setattr(nameserver, "_refresh_cert", unchanged_refresh)
        await _query(nameserver)
        await _query(nameserver)

        assert refreshes == 1
        await nameserver.stop()
    finally:
        transport.close()


async def test_expiring_cert_refreshes_before_query() -> None:
    """证书剩余寿命低于阈值时，查询前主动刷新获取新证书。"""
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        assert nameserver._cert is not None
        old_serial = nameserver._cert.serial
        # 把已安装证书的过期时刻改到阈值内（模拟临期），服务端同时发布新证书。
        object.__setattr__(nameserver._cert, "expire", int(time()) + 60)
        server.certs = [(2, old_serial + 1, -100, 86400, False)]

        response = await _query(nameserver)
        assert response.answer[0][0].address == PADDED_ANSWER_IP
        assert nameserver._cert is not None
        assert nameserver._cert.serial == old_serial + 1
        await nameserver.stop()
    finally:
        transport.close()


async def test_cert_refresh_failure_keeps_old_cert() -> None:
    """刷新失败（无有效证书）时沿用旧证书，重试用尽后向上抛错。"""
    server = _FakeDnsCryptServer()
    transport, port = await _start_udp(server)
    try:
        nameserver = await _make_nameserver(server, port)
        old_cert = nameserver._cert
        server.server_private = PrivateKey.generate()
        # 服务端只发布坏签名证书：刷新拿不到有效证书。旧密钥加密的查询
        # 在假服务器上无应答（解密失败被丢弃），最终按超时上抛。
        server.certs = [(2, 99, -100, 86400, True)]

        with pytest.raises(TimeoutError):
            await _query(nameserver)
        assert nameserver._cert is old_cert
        await nameserver.stop()
    finally:
        transport.close()
