"""DNSCrypt v2 crypto_box XChaCha20 bindings absent from PyNaCl's public API.

PyNaCl supplies key generation and certificate verification.  The three box
operations below call the same libsodium primitives used by DNSCrypt servers.
"""

import ctypes
import ctypes.util
import os
from functools import lru_cache

from nacl.exceptions import CryptoError

_PREFIX = "crypto_box_curve25519xchacha20poly1305_"
_KEY_SIZE = 32
_NONCE_SIZE = 24
_MAC_SIZE = 16


@lru_cache(maxsize=1)
def _library() -> ctypes.CDLL:
    explicit = os.environ.get("SMARTDNS_LIBSODIUM_PATH")
    candidates = (
        [explicit]
        if explicit
        else [
            ctypes.util.find_library("sodium"),
            ctypes.util.find_library("libsodium"),
            "libsodium.dll" if os.name == "nt" else "libsodium.so",
            "libsodium.dylib",
        ]
    )
    library = None
    load_error: OSError | None = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            library = ctypes.CDLL(candidate)
            break
        except OSError as error:
            load_error = error
            continue
    if library is None:
        raise RuntimeError(
            "DNSCrypt v2 需要可动态加载的 libsodium；请安装 libsodium，"
            "或将 SMARTDNS_LIBSODIUM_PATH 设为库文件的绝对路径"
        ) from load_error
    try:
        library.sodium_init.argtypes = []
        library.sodium_init.restype = ctypes.c_int
        if library.sodium_init() < 0:
            raise RuntimeError("libsodium 初始化失败")
        before = getattr(library, _PREFIX + "beforenm")
        before.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        before.restype = ctypes.c_int
        encrypt = getattr(library, _PREFIX + "easy_afternm")
        encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_ulonglong,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        encrypt.restype = ctypes.c_int
        decrypt = getattr(library, _PREFIX + "open_easy_afternm")
        decrypt.argtypes = encrypt.argtypes
        decrypt.restype = ctypes.c_int
    except AttributeError as error:
        raise RuntimeError(
            "已加载的 libsodium 不支持 DNSCrypt v2 XChaCha20 crypto_box"
        ) from error
    return library


def require_libsodium() -> None:
    """Fail before network I/O if DNSCrypt's native primitive is unavailable."""
    _library()


def box_beforenm(private_key: bytes, public_key: bytes) -> bytes:
    if len(private_key) != _KEY_SIZE or len(public_key) != _KEY_SIZE:
        raise ValueError("DNSCrypt X25519 密钥必须是 32 字节")
    result = ctypes.create_string_buffer(_KEY_SIZE)
    if getattr(_library(), _PREFIX + "beforenm")(result, public_key, private_key) != 0:
        raise CryptoError("DNSCrypt 共享密钥派生失败")
    return result.raw


def box_easy_afternm(message: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(nonce) != _NONCE_SIZE or len(key) != _KEY_SIZE:
        raise ValueError("DNSCrypt nonce 或共享密钥长度非法")
    result = ctypes.create_string_buffer(len(message) + _MAC_SIZE)
    if (
        getattr(_library(), _PREFIX + "easy_afternm")(
            result, message, len(message), nonce, key
        )
        != 0
    ):
        raise CryptoError("DNSCrypt 查询加密失败")
    return result.raw


def box_open_easy_afternm(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(nonce) != _NONCE_SIZE or len(key) != _KEY_SIZE:
        raise ValueError("DNSCrypt nonce 或共享密钥长度非法")
    if len(ciphertext) < _MAC_SIZE:
        raise CryptoError("DNSCrypt 密文过短")
    result = ctypes.create_string_buffer(len(ciphertext) - _MAC_SIZE)
    if (
        getattr(_library(), _PREFIX + "open_easy_afternm")(
            result, ciphertext, len(ciphertext), nonce, key
        )
        != 0
    ):
        raise CryptoError("DNSCrypt MAC 校验失败")
    return result.raw
