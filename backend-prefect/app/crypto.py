"""Cifrado en reposo de la semilla TOTP con AES-256-GCM.

La semilla no se puede hashear: el servidor necesita recuperarla para calcular
HMAC-SHA1 en cada verificación. Por eso se CIFRA (reversible con la llave) en
lugar de hashearse (irreversible), que es lo que se hace con las contraseñas.

Formato guardado en mfa_config.secret_base32:
    aes256gcm$<base64url(nonce de 12 bytes || texto cifrado || tag de 16 bytes)>
"""
import base64
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import config

PREFIX = "aes256gcm$"
NONCE_BYTES = 12


def _key() -> bytes:
    key = base64.urlsafe_b64decode(config.TOTP_ENCRYPTION_KEY)
    if len(key) != 32:
        raise RuntimeError("TOTP_ENCRYPTION_KEY debe ser de 32 bytes (AES-256) en base64")
    return key


def encrypt_secret(secret_base32: str, user_id: uuid.UUID) -> str:
    nonce = os.urandom(NONCE_BYTES)  # nonce aleatorio y único por cifrado
    # El user_id va como dato asociado (AAD): el cifrado solo se descifra para ese usuario.
    ciphertext = AESGCM(_key()).encrypt(nonce, secret_base32.encode(), str(user_id).encode())
    return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_secret(stored: str, user_id: uuid.UUID) -> str:
    if not stored.startswith(PREFIX):
        raise ValueError("La semilla guardada no está cifrada con AES-256-GCM")
    blob = base64.urlsafe_b64decode(stored[len(PREFIX):])
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    # Si alguien altera el valor en la base o lo copia a otro usuario, el tag GCM falla.
    return AESGCM(_key()).decrypt(nonce, ciphertext, str(user_id).encode()).decode()
