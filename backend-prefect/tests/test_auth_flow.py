import time
import uuid

from app import totp


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _enrolled_user(client) -> tuple[dict, str, list[str]]:
    creds = {"username": f"user_{uuid.uuid4().hex[:8]}", "password": "secreto123"}
    assert client.post("/auth/register", json=creds).status_code == 201

    login = client.post("/auth/login", json=creds).json()
    assert login["scope"] == "mfa:enroll"

    setup = client.post("/auth/2fa/setup", headers=_bearer(login["pre_auth_token"])).json()
    assert setup["status"] == "PENDING_VERIFICATION"
    assert setup["qr_code"].startswith("data:image/svg+xml;base64,")
    secret = setup["secret"]

    # Se activa con el código de la ventana anterior para dejar libre el actual.
    first_code = totp.totp(secret, time.time() - 30)
    activated = client.post("/auth/2fa/activate", json={"code": first_code},
                            headers=_bearer(login["pre_auth_token"])).json()
    assert activated["status"] == "ACTIVE"
    assert activated["matched_window"] == "C-1"
    return creds, secret, activated["backup_codes"]


def _pre_auth(client, creds) -> str:
    login = client.post("/auth/login", json=creds).json()
    assert login["scope"] == "mfa:verify"
    return login["pre_auth_token"]


def test_step_up_totp_and_replay(client):
    creds, secret, _ = _enrolled_user(client)
    pre_auth = _pre_auth(client, creds)

    # El pre_auth_token no abre la bóveda.
    assert client.get("/api/boveda-secreta", headers=_bearer(pre_auth)).status_code == 401

    code = totp.totp(secret)
    res = client.post("/auth/verify-2fa", json={"code": code}, headers=_bearer(pre_auth))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["mfa_verified"] is True
    assert body["matched_window"] == "C"

    vault = client.get("/api/boveda-secreta", headers=_bearer(body["access_token"]))
    assert vault.status_code == 200
    assert vault.json()["mfa_verified"] is True

    # Mismo pre_auth_token: ya fue canjeado.
    again = client.post("/auth/verify-2fa", json={"code": code}, headers=_bearer(pre_auth))
    assert again.status_code == 401

    # Login nuevo + mismo código -> ataque de repetición.
    replay = client.post("/auth/verify-2fa", json={"code": code}, headers=_bearer(_pre_auth(client, creds)))
    assert replay.status_code == 409
    assert replay.json()["error"] == "replay_attack_detected"


def test_backup_code_is_single_use(client):
    creds, _, backup_codes = _enrolled_user(client)
    code = backup_codes[0].lower()  # se normaliza en el backend

    ok = client.post("/auth/verify-2fa", json={"code": code, "method": "backup"},
                     headers=_bearer(_pre_auth(client, creds)))
    assert ok.status_code == 200, ok.text
    assert ok.json()["method"] == "backup"

    from app.replay_cache import used_codes
    used_codes.clear()  # aunque expire la caché, la BD impide reutilizarlo

    reused = client.post("/auth/verify-2fa", json={"code": code, "method": "backup"},
                         headers=_bearer(_pre_auth(client, creds)))
    assert reused.status_code == 401
    assert reused.json()["error"] == "invalid_second_factor"


def test_wrong_code_and_attempt_limit(client):
    creds, secret, _ = _enrolled_user(client)
    pre_auth = _pre_auth(client, creds)
    wrong = totp.totp(secret, time.time() + 300)
    for _ in range(5):
        res = client.post("/auth/verify-2fa", json={"code": wrong}, headers=_bearer(pre_auth))
        assert res.status_code == 401
    blocked = client.post("/auth/verify-2fa", json={"code": totp.totp(secret)}, headers=_bearer(pre_auth))
    assert blocked.status_code == 429


def test_cannot_reprovision_active_2fa(client):
    creds, _, _ = _enrolled_user(client)
    # Con 2FA ACTIVE el login entrega scope mfa:verify, que no sirve para setup.
    res = client.post("/auth/2fa/setup", headers=_bearer(_pre_auth(client, creds)))
    assert res.status_code == 401


def test_invalid_password(client):
    res = client.post("/auth/login", json={"username": "nadie", "password": "incorrecta"})
    assert res.status_code == 401
    assert res.json()["error"] == "invalid_credentials"
