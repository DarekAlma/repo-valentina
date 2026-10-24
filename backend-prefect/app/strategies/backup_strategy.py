import hashlib
import secrets
import uuid

from sqlalchemy import update

from app.db import BackupCode, session_scope
from app.strategies.base import SecondFactorStrategy, VerificationResult

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin 0/O ni 1/I para evitar confusiones


def normalize_backup_code(code: str) -> str:
    return code.replace("-", "").replace(" ", "").upper()


def hash_backup_code(code: str) -> str:
    # Los códigos tienen ~40 bits aleatorios y son de un solo uso: SHA-256 basta.
    return hashlib.sha256(normalize_backup_code(code).encode()).hexdigest()


def generate_backup_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


class BackupCodeStrategy(SecondFactorStrategy):
    """Códigos de emergencia de un solo uso por si el usuario pierde el teléfono."""

    name = "backup"

    def verify(self, user_id: uuid.UUID, code: str) -> VerificationResult:
        # UPDATE condicionado: marcar y validar en una sola sentencia hace
        # imposible que dos peticiones simultáneas canjeen el mismo código.
        with session_scope() as session:
            result = session.execute(
                update(BackupCode)
                .where(
                    BackupCode.user_id == user_id,
                    BackupCode.code_hash == hash_backup_code(code),
                    BackupCode.used.is_not(True),
                )
                .values(used=True)
            )
        if result.rowcount != 1:
            return VerificationResult(False, self.name, "Código de respaldo inválido o ya usado")
        return VerificationResult(True, self.name, "Código de respaldo válido (consumido)")
