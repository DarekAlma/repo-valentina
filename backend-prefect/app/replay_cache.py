"""Cachés en memoria con expiración (sustituto de Redis para el laboratorio)."""
import threading
import time
from collections.abc import Hashable

from app import config


class ExpiringSet:
    """Conjunto con TTL por elemento y alta atómica (equivalente a SET NX EX)."""

    def __init__(self, ttl_seconds: int):
        self._ttl = ttl_seconds
        self._items: dict[Hashable, float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for key in [k for k, expires in self._items.items() if expires <= now]:
            del self._items[key]

    def contains(self, key: Hashable) -> bool:
        with self._lock:
            self._purge(time.monotonic())
            return key in self._items

    def add_if_absent(self, key: Hashable) -> bool:
        """Registra la clave; devuelve False si ya existía (alguien ganó la carrera)."""
        with self._lock:
            now = time.monotonic()
            self._purge(now)
            if key in self._items:
                return False
            self._items[key] = now + self._ttl
            return True

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class AttemptCounter:
    """Cuenta intentos fallidos por pre_auth_token para frenar fuerza bruta."""

    def __init__(self, ttl_seconds: int):
        self._ttl = ttl_seconds
        self._counts: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> int:
        with self._lock:
            count, expires = self._counts.get(key, (0, 0.0))
            return count if expires > time.monotonic() else 0

    def increment(self, key: str) -> int:
        with self._lock:
            now = time.monotonic()
            count, expires = self._counts.get(key, (0, 0.0))
            count = count + 1 if expires > now else 1
            self._counts[key] = (count, now + self._ttl)
            return count

    def clear(self) -> None:
        with self._lock:
            self._counts.clear()


# (user_id, código) usados en los últimos 90 s
used_codes = ExpiringSet(config.REPLAY_WINDOW_SECONDS)
# jti de pre_auth_tokens ya canjeados: cada uno sirve para una sola elevación
consumed_pre_auth = ExpiringSet(config.PRE_AUTH_TTL_SECONDS)
failed_attempts = AttemptCounter(config.PRE_AUTH_TTL_SECONDS)
