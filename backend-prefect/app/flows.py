"""Pipelines de autenticación orquestados y observados con Prefect.

Las contraseñas y tokens viajan como SecretStr: Prefect los muestra
ofuscados ("**********") en los parámetros del flow run en la UI.
"""
import uuid
from dataclasses import asdict

from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE
from pydantic import SecretStr
from sqlalchemy import delete, select

from app import config, security, totp
from app.crypto import encrypt_secret
from app.db import BackupCode, TwoFactorConfig, User, session_scope, utcnow
from app.errors import (
    InvalidCredentials,
    InvalidPreAuthToken,
    InvalidSecondFactor,
    ReplayAttackDetected,
    TooManyAttempts,
)
from app.replay_cache import consumed_pre_auth, failed_attempts, used_codes
from app.state_machine import TwoFactorStatus, ensure_transition
from app.strategies import TOTPStrategy, get_strategy
from app.strategies.backup_strategy import (
    generate_backup_codes,
    hash_backup_code,
    normalize_backup_code,
)

# Sin caché ni reintentos: cada intento de autenticación debe ejecutarse de verdad.
TASK_OPTS = {"cache_policy": NO_CACHE, "retries": 0}

_DUMMY_HASH = security.hash_password("timing-equalizer")

_DRIFT_HINT = {
    "C-1": "el reloj del celular va ~30 s ATRASADO",
    "C": "reloj del celular sincronizado",
    "C+1": "el reloj del celular va ~30 s ADELANTADO",
}


def _mask(code: str) -> str:
    return code[:2] + "*" * (len(code) - 2)


# --------------------------------------------------------------------------- #
# Tasks compartidas
# --------------------------------------------------------------------------- #
@task(name="validate_pre_auth_state", **TASK_OPTS)
def validate_pre_auth_state(pre_auth_token: SecretStr, required_scope: str) -> dict:
    logger = get_run_logger()
    claims = security.decode_pre_auth_token(pre_auth_token.get_secret_value(), required_scope)
    jti = claims["jti"]
    if consumed_pre_auth.contains(jti):
        raise InvalidPreAuthToken("Este pre_auth_token ya fue canjeado; inicia sesión de nuevo")
    attempts = failed_attempts.get(jti)
    if attempts >= config.MAX_MFA_ATTEMPTS:
        raise TooManyAttempts(f"Se agotaron los {config.MAX_MFA_ATTEMPTS} intentos; inicia sesión de nuevo")
    logger.info(
        "pre_auth_token válido: user_id=%s scope=%s intentos_fallidos=%d",
        claims["sub"], claims["scope"], attempts,
    )
    return claims


@task(name="check_anti_replay_cache", **TASK_OPTS)
def check_anti_replay_cache(user_id: uuid.UUID, code: str) -> None:
    logger = get_run_logger()
    if used_codes.contains((user_id, code)):
        logger.error(
            "REPLAY ATTACK: el código %s ya fue usado por user_id=%s en los últimos %d s",
            _mask(code), user_id, config.REPLAY_WINDOW_SECONDS,
        )
        raise ReplayAttackDetected(
            f"El código ya fue utilizado en los últimos {config.REPLAY_WINDOW_SECONDS} segundos"
        )
    logger.info("Código %s no está en la caché anti-replay", _mask(code))


def _claim_code(user_id: uuid.UUID, code: str) -> None:
    # Alta atómica: si otra petición concurrente pasó check_anti_replay_cache
    # con el mismo código, solo una gana aquí.
    if not used_codes.add_if_absent((user_id, code)):
        raise ReplayAttackDetected("El código fue utilizado por otra petición concurrente")


# --------------------------------------------------------------------------- #
# Login (factor 1): usuario + contraseña -> pre_auth_token
# --------------------------------------------------------------------------- #
@task(name="authenticate_credentials", **TASK_OPTS)
def authenticate_credentials(username: str, password: SecretStr) -> dict:
    logger = get_run_logger()
    with session_scope() as session:
        user = session.scalar(select(User).where(User.username == username))
        cfg = (
            session.scalar(select(TwoFactorConfig).where(TwoFactorConfig.user_id == user.id))
            if user else None
        )
    stored = user.password_hash if user else _DUMMY_HASH
    if not security.verify_password(password.get_secret_value(), stored) or user is None:
        logger.warning("Credenciales inválidas para '%s'", username)
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    status = TwoFactorStatus(cfg.status).value if cfg else None
    logger.info("Contraseña válida: user_id=%s estado_2fa=%s", user.id, status or "SIN_2FA")
    return {"user_id": user.id, "username": user.username, "mfa_status": status}


@task(name="issue_pre_auth_token", **TASK_OPTS)
def issue_pre_auth_token(user_id: uuid.UUID, username: str, mfa_status: str | None) -> dict:
    logger = get_run_logger()
    if mfa_status == TwoFactorStatus.ACTIVE.value:
        scope, next_step = security.SCOPE_MFA_VERIFY, "/auth/verify-2fa"
    else:
        scope, next_step = security.SCOPE_MFA_ENROLL, "/auth/2fa/setup"
    token = security.create_pre_auth_token(user_id, username, scope)
    logger.info("pre_auth_token emitido (scope=%s, ttl=%ds)", scope, config.PRE_AUTH_TTL_SECONDS)
    return {
        "pre_auth_token": token,
        "token_type": "pre_auth",
        "scope": scope,
        "mfa_status": mfa_status,
        "next": next_step,
        "expires_in": config.PRE_AUTH_TTL_SECONDS,
    }


@flow(name="login-flow", flow_run_name="login-{username}")
def login_flow(username: str, password: SecretStr) -> dict:
    user = authenticate_credentials(username, password)
    return issue_pre_auth_token(user["user_id"], user["username"], user["mfa_status"])


# --------------------------------------------------------------------------- #
# Aprovisionamiento 2FA (Process Manager): SIN_2FA -> PENDING_VERIFICATION
# --------------------------------------------------------------------------- #
@task(name="create_pending_2fa_config", **TASK_OPTS)
def create_pending_2fa_config(user_id: uuid.UUID) -> str:
    logger = get_run_logger()
    secret = totp.generate_secret()
    secret_encrypted = encrypt_secret(secret, user_id)
    with session_scope() as session:
        cfg = session.scalar(select(TwoFactorConfig).where(TwoFactorConfig.user_id == user_id))
        current = TwoFactorStatus(cfg.status) if cfg else None
        ensure_transition(current, TwoFactorStatus.PENDING_VERIFICATION)
        if cfg is None:
            cfg = TwoFactorConfig(user_id=user_id, secret_encrypted=secret_encrypted,
                                  status=TwoFactorStatus.PENDING_VERIFICATION.value)
            session.add(cfg)
        else:
            cfg.secret_encrypted = secret_encrypted
            cfg.created_at = utcnow()
    logger.info(
        "Estado 2FA de user_id=%s: %s -> PENDING_VERIFICATION (semilla guardada con AES-256-GCM)",
        user_id, current.value if current else "SIN_2FA",
    )
    return secret


@task(name="build_provisioning_uri", **TASK_OPTS)
def build_provisioning_uri(username: str, secret: str) -> str:
    uri = totp.build_otpauth_uri(secret, username, config.TOTP_ISSUER)
    get_run_logger().info("URI otpauth generada para '%s' (issuer=%s)", username, config.TOTP_ISSUER)
    return uri


@flow(name="2fa-provisioning-flow")
def provision_2fa_flow(pre_auth_token: SecretStr) -> dict:
    claims = validate_pre_auth_state(pre_auth_token, security.SCOPE_MFA_ENROLL)
    user_id = uuid.UUID(claims["sub"])
    secret = create_pending_2fa_config(user_id)
    uri = build_provisioning_uri(claims["username"], secret)
    return {"secret": secret, "otpauth_uri": uri, "status": TwoFactorStatus.PENDING_VERIFICATION.value}


# --------------------------------------------------------------------------- #
# Activación 2FA: PENDING_VERIFICATION -> ACTIVE con el primer código válido
# --------------------------------------------------------------------------- #
@task(name="verify_first_totp_code", **TASK_OPTS)
def verify_first_totp_code(user_id: uuid.UUID, code: str, jti: str) -> dict:
    logger = get_run_logger()
    result = TOTPStrategy(required_status=TwoFactorStatus.PENDING_VERIFICATION).verify(user_id, code)
    if not result.success:
        failed_attempts.increment(jti)
        logger.warning("Primer código rechazado: %s", result.detail)
        raise InvalidSecondFactor(result.detail)
    logger.info("Primer código válido: %s (%s)", result.detail, _DRIFT_HINT[result.matched_window])
    return asdict(result)


@task(name="activate_2fa_config", **TASK_OPTS)
def activate_2fa_config(user_id: uuid.UUID, code: str, jti: str) -> list[str]:
    logger = get_run_logger()
    _claim_code(user_id, code)
    codes = generate_backup_codes()
    with session_scope() as session:
        cfg = session.scalar(select(TwoFactorConfig).where(TwoFactorConfig.user_id == user_id))
        ensure_transition(TwoFactorStatus(cfg.status), TwoFactorStatus.ACTIVE)
        cfg.status = TwoFactorStatus.ACTIVE.value
        cfg.activated_at = utcnow()
        session.execute(delete(BackupCode).where(BackupCode.user_id == user_id))
        session.add_all(BackupCode(user_id=user_id, code_hash=hash_backup_code(c)) for c in codes)
    consumed_pre_auth.add_if_absent(jti)
    logger.info("Estado 2FA de user_id=%s: PENDING_VERIFICATION -> ACTIVE (%d códigos de respaldo)",
                user_id, len(codes))
    return codes


@flow(name="2fa-activation-flow")
def activate_2fa_flow(pre_auth_token: SecretStr, code: str) -> dict:
    code = code.strip()
    claims = validate_pre_auth_state(pre_auth_token, security.SCOPE_MFA_ENROLL)
    user_id = uuid.UUID(claims["sub"])
    check_anti_replay_cache(user_id, code)
    result = verify_first_totp_code(user_id, code, claims["jti"])
    backup_codes = activate_2fa_config(user_id, code, claims["jti"])
    return {
        "status": TwoFactorStatus.ACTIVE.value,
        "matched_window": result["matched_window"],
        "backup_codes": backup_codes,
    }


# --------------------------------------------------------------------------- #
# Step-Up: pre_auth_token + segundo factor -> access_token (mfa_verified: true)
# --------------------------------------------------------------------------- #
@task(name="execute_mfa_strategy", **TASK_OPTS)
def execute_mfa_strategy(user_id: uuid.UUID, method: str, code: str, jti: str) -> dict:
    logger = get_run_logger()
    strategy = get_strategy(method)
    logger.info("Estrategia seleccionada: %s", type(strategy).__name__)
    result = strategy.verify(user_id, code)
    if not result.success:
        attempts = failed_attempts.increment(jti)
        logger.warning("Segundo factor rechazado (%s). Intento fallido %d/%d",
                       result.detail, attempts, config.MAX_MFA_ATTEMPTS)
        raise InvalidSecondFactor(result.detail)
    if result.matched_window:
        logger.info("TOTP válido para user_id=%s -> ventana %s: %s",
                    user_id, result.matched_window, _DRIFT_HINT[result.matched_window])
    else:
        logger.info("Segundo factor válido: %s", result.detail)
    return asdict(result)


@task(name="issue_elevated_session", **TASK_OPTS)
def issue_elevated_session(user_id: uuid.UUID, username: str, code: str, jti: str, method: str) -> dict:
    logger = get_run_logger()
    _claim_code(user_id, code)
    if not consumed_pre_auth.add_if_absent(jti):
        raise InvalidPreAuthToken("Este pre_auth_token ya fue canjeado")
    token = security.create_access_token(user_id, username, amr=method)
    logger.info("Código marcado como usado (%d s) y access_token emitido con mfa_verified=true",
                config.REPLAY_WINDOW_SECONDS)
    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_verified": True,
        "expires_in": config.ACCESS_TTL_SECONDS,
    }


@flow(name="2fa-verification-flow", flow_run_name="verify-2fa-{method}")
def verify_2fa_flow(pre_auth_token: SecretStr, code: str, method: str = "totp") -> dict:
    code = normalize_backup_code(code) if method == "backup" else code.strip()
    claims = validate_pre_auth_state(pre_auth_token, security.SCOPE_MFA_VERIFY)
    user_id = uuid.UUID(claims["sub"])
    check_anti_replay_cache(user_id, code)
    result = execute_mfa_strategy(user_id, method, code, claims["jti"])
    session = issue_elevated_session(user_id, claims["username"], code, claims["jti"], method)
    return {**session, "method": method, "matched_window": result["matched_window"]}
