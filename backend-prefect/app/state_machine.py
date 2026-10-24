"""Máquina de estados del aprovisionamiento 2FA (Process Manager).

    (sin 2FA) --setup--> PENDING_VERIFICATION --primer código válido--> ACTIVE
                              |   ^
                              +---+  (regenerar QR mientras siga pendiente)

Un usuario que genera el QR y nunca lo escanea se queda en PENDING_VERIFICATION
y sigue pudiendo iniciar sesión solo con contraseña para terminar la activación.
"""
from enum import Enum

from app.errors import InvalidStateTransition


class TwoFactorStatus(str, Enum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


_ALLOWED: dict[TwoFactorStatus | None, set[TwoFactorStatus]] = {
    None: {TwoFactorStatus.PENDING_VERIFICATION},
    TwoFactorStatus.PENDING_VERIFICATION: {
        TwoFactorStatus.PENDING_VERIFICATION,
        TwoFactorStatus.ACTIVE,
    },
    TwoFactorStatus.ACTIVE: set(),
}


def ensure_transition(current: TwoFactorStatus | None, target: TwoFactorStatus) -> None:
    if target not in _ALLOWED[current]:
        origin = current.value if current else "SIN_2FA"
        raise InvalidStateTransition(f"Transición no permitida: {origin} -> {target.value}")
