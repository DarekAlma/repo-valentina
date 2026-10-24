"""Configuración central. Se importa antes que Prefect para fijar PREFECT_API_URL."""
import logging
import os
import secrets

from dotenv import load_dotenv

load_dotenv()

# Si no se indica otra cosa, los flows se reportan al servidor local de
# `prefect server start`. Sin esto Prefect levantaría un servidor efímero y
# las ejecuciones no aparecerían en el dashboard.
os.environ.setdefault("PREFECT_API_URL", "http://127.0.0.1:4200/api")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

JWT_SECRET = os.getenv("JWT_SECRET") or ""
if not JWT_SECRET:
    # Secreto aleatorio por arranque: los tokens dejan de valer al reiniciar,
    # aceptable en laboratorio y mejor que un secreto fijo en el código.
    JWT_SECRET = secrets.token_urlsafe(32)
    logging.getLogger(__name__).warning("JWT_SECRET no definido; usando uno aleatorio temporal")

TOTP_ISSUER = os.getenv("TOTP_ISSUER", "PatronesLab")

# Llave AES-256 (32 bytes en base64) para cifrar las semillas TOTP en la base.
# No se genera al azar: si cambia, las semillas guardadas dejan de poder descifrarse.
TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY", "")
if not TOTP_ENCRYPTION_KEY:
    raise RuntimeError(
        "Falta TOTP_ENCRYPTION_KEY en .env. Genera una con: "
        'python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"'
    )

PRE_AUTH_TTL_SECONDS = 5 * 60
ACCESS_TTL_SECONDS = 15 * 60
REPLAY_WINDOW_SECONDS = 90  # C-1, C y C+1 -> 3 ventanas de 30 s
MAX_MFA_ATTEMPTS = 5  # intentos fallidos permitidos por pre_auth_token
