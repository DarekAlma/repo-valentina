"""Hash de contraseñas (scrypt) y emisión/validación de JWT."""
import hashlib
import hmac
import os
import time
import uuid

import jwt

from app import config
from app.errors import InvalidAccessToken, InvalidPreAuthToken

ALGORITHM = "HS256"

TOKEN_PRE_AUTH = "pre_auth"
TOKEN_ACCESS = "access"

SCOPE_MFA_VERIFY = "mfa:verify"  # el usuario ya tiene 2FA ACTIVE
SCOPE_MFA_ENROLL = "mfa:enroll"  # el usuario aún no termina de activar 2FA

_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    derived = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(derived.hex(), hash_hex)


def _encode(claims: dict, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + ttl_seconds, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, config.JWT_SECRET, algorithm=ALGORITHM)


def create_pre_auth_token(user_id: uuid.UUID, username: str, scope: str) -> str:
    return _encode(
        {"sub": str(user_id), "username": username, "typ": TOKEN_PRE_AUTH, "scope": scope},
        config.PRE_AUTH_TTL_SECONDS,
    )


def create_access_token(user_id: uuid.UUID, username: str, amr: str) -> str:
    return _encode(
        {
            "sub": str(user_id),
            "username": username,
            "typ": TOKEN_ACCESS,
            "mfa_verified": True,
            "amr": ["pwd", amr],
        },
        config.ACCESS_TTL_SECONDS,
    )


def decode_pre_auth_token(token: str, required_scope: str) -> dict:
    try:
        claims = jwt.decode(token, config.JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidPreAuthToken(f"pre_auth_token inválido o expirado: {exc}") from None
    if claims.get("typ") != TOKEN_PRE_AUTH:
        raise InvalidPreAuthToken("El token no es un pre_auth_token")
    if claims.get("scope") != required_scope:
        raise InvalidPreAuthToken(f"El token no tiene el scope requerido ({required_scope})")
    return claims


def decode_access_token(token: str) -> dict:
    try:
        claims = jwt.decode(token, config.JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidAccessToken(f"access_token inválido o expirado: {exc}") from None
    if claims.get("typ") != TOKEN_ACCESS or claims.get("mfa_verified") is not True:
        raise InvalidAccessToken("Se requiere un access_token con mfa_verified: true")
    return claims
