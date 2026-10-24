import uuid

import pytest
from cryptography.exceptions import InvalidTag

from app import totp
from app.crypto import PREFIX, decrypt_secret, encrypt_secret


def test_secret_roundtrip_and_not_plaintext():
    user_id = uuid.uuid4()
    secret = totp.generate_secret()
    stored = encrypt_secret(secret, user_id)
    assert stored.startswith(PREFIX)
    assert secret not in stored
    assert decrypt_secret(stored, user_id) == secret


def test_same_secret_encrypts_differently_each_time():
    user_id = uuid.uuid4()
    secret = totp.generate_secret()
    assert encrypt_secret(secret, user_id) != encrypt_secret(secret, user_id)  # nonce aleatorio


def test_secret_bound_to_its_user():
    stored = encrypt_secret(totp.generate_secret(), uuid.uuid4())
    with pytest.raises(InvalidTag):
        decrypt_secret(stored, uuid.uuid4())
