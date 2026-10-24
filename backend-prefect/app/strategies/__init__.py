from app.errors import InvalidSecondFactor
from app.strategies.backup_strategy import BackupCodeStrategy
from app.strategies.base import SecondFactorStrategy, VerificationResult
from app.strategies.totp_strategy import TOTPStrategy

_REGISTRY: dict[str, type[SecondFactorStrategy]] = {
    TOTPStrategy.name: TOTPStrategy,
    BackupCodeStrategy.name: BackupCodeStrategy,
}


def get_strategy(method: str) -> SecondFactorStrategy:
    try:
        return _REGISTRY[method]()
    except KeyError:
        raise InvalidSecondFactor(f"Método de segundo factor desconocido: {method}") from None


__all__ = [
    "BackupCodeStrategy",
    "SecondFactorStrategy",
    "TOTPStrategy",
    "VerificationResult",
    "get_strategy",
]
