import base64

from app import totp

# Vectores del Apéndice B de RFC 6238 (SHA-1, semilla "12345678901234567890").
# El RFC publica 8 dígitos; los 6 dígitos son los últimos 6.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}


def test_rfc6238_vectors():
    key = totp.decode_base32(RFC_SECRET)
    for unix_time, expected in RFC_VECTORS.items():
        counter = totp.time_counter(unix_time)
        assert totp.hotp(key, counter, digits=8) == expected
        assert totp.totp(RFC_SECRET, unix_time) == expected[-6:]


def test_match_window_reports_drift():
    secret = totp.generate_secret()
    now = 1_700_000_000
    assert totp.match_window(secret, totp.totp(secret, now - 30), now) == -1
    assert totp.match_window(secret, totp.totp(secret, now), now) == 0
    assert totp.match_window(secret, totp.totp(secret, now + 30), now) == 1
    assert totp.match_window(secret, totp.totp(secret, now + 90), now) is None
    assert totp.match_window(secret, "abc123", now) is None


def test_otpauth_uri_contains_secret():
    uri = totp.build_otpauth_uri("JBSWY3DPEHPK3PXP", "ana", "PatronesLab")
    assert uri.startswith("otpauth://totp/PatronesLab%3Aana?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
