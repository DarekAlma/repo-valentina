"""TOTP (RFC 6238) implementado desde cero sobre la librería estándar.

Solo se usan primitivas estándar: HMAC-SHA1 (hmac/hashlib) y Base32 (base64).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
WINDOW_LABELS = {-1: "C-1", 0: "C", 1: "C+1"}


def generate_secret(num_bytes: int = 20) -> str:
    """Semilla aleatoria de 160 bits codificada en Base32 sin padding."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def decode_base32(secret: str) -> bytes:
    cleaned = secret.replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def time_counter(unix_time: float | None = None) -> int:
    """C = floor(UnixTime / 30)."""
    now = time.time() if unix_time is None else unix_time
    return int(now // STEP_SECONDS)


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    message = struct.pack(">Q", counter)  # 8 bytes, big-endian
    digest = hmac.new(key, message, hashlib.sha1).digest()  # 20 bytes
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret: str, unix_time: float | None = None) -> str:
    return hotp(decode_base32(secret), time_counter(unix_time))


def match_window(secret: str, code: str, unix_time: float | None = None) -> int | None:
    """Devuelve el desfase (-1, 0, 1) de la ventana que coincide, o None."""
    if not (len(code) == DIGITS and code.isdigit()):
        return None
    key = decode_base32(secret)
    counter = time_counter(unix_time)
    matched = None
    # Se evalúan las 3 ventanas siempre, para no filtrar información por tiempo.
    for drift in (-1, 0, 1):
        if hmac.compare_digest(hotp(key, counter + drift), code):
            matched = drift
    return matched


def build_otpauth_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}")
    params = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": STEP_SECONDS,
    })
    return f"otpauth://totp/{label}?{params}"
