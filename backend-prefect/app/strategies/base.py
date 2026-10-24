import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    method: str
    detail: str
    matched_window: str | None = None  # "C-1", "C" o "C+1" (solo TOTP)


class SecondFactorStrategy(ABC):
    """Contrato común para cualquier segundo factor intercambiable."""

    name: str

    @abstractmethod
    def verify(self, user_id: uuid.UUID, code: str) -> VerificationResult:
        ...
