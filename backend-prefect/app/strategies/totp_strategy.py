import uuid

from sqlalchemy import select

from app import totp
from app.crypto import decrypt_secret
from app.db import TwoFactorConfig, session_scope
from app.state_machine import TwoFactorStatus
from app.strategies.base import SecondFactorStrategy, VerificationResult


class TOTPStrategy(SecondFactorStrategy):
    """Valida el código de 6 dígitos contra las ventanas C-1, C y C+1."""

    name = "totp"

    def __init__(self, required_status: TwoFactorStatus = TwoFactorStatus.ACTIVE):
        # La activación usa la misma estrategia pero sobre la config PENDING.
        self.required_status = required_status

    def verify(self, user_id: uuid.UUID, code: str) -> VerificationResult:
        with session_scope() as session:
            cfg = session.scalar(select(TwoFactorConfig).where(TwoFactorConfig.user_id == user_id))
        if cfg is None or TwoFactorStatus(cfg.status) != self.required_status:
            return VerificationResult(False, self.name, f"No hay 2FA en estado {self.required_status.value}")

        secret = decrypt_secret(cfg.secret_encrypted, user_id)  # AES-256-GCM -> Base32
        drift = totp.match_window(secret, code)
        if drift is None:
            return VerificationResult(False, self.name, "Código TOTP no coincide en C-1, C ni C+1")
        window = totp.WINDOW_LABELS[drift]
        return VerificationResult(True, self.name, f"Coincidió en la ventana {window}", window)
