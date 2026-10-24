import base64
import io
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from app import config  # noqa: F401  (fija PREFECT_API_URL antes de importar Prefect)

import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import security
from app.db import User, init_db, session_scope
from app.errors import AuthFlowError, UserAlreadyExists
from app.flows import activate_2fa_flow, login_flow, provision_2fa_flow, verify_2fa_flow

WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Laboratorio 2FA TOTP + Prefect", lifespan=lifespan)
bearer = HTTPBearer()


@app.exception_handler(AuthFlowError)
async def auth_error_handler(_: Request, exc: AuthFlowError):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.error_code, "detail": str(exc)})


class CredentialsIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: SecretStr = Field(min_length=6)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=16)
    method: Literal["totp", "backup"] = "totp"


def _bearer_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> SecretStr:
    return SecretStr(credentials.credentials)


def _qr_data_uri(text: str) -> str:
    image = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode()


@app.get("/", include_in_schema=False)
def web_app():
    return FileResponse(WEB_DIR / "index.html")


@app.post("/auth/register", status_code=201)
def register(body: CredentialsIn):
    try:
        with session_scope() as session:
            if session.scalar(select(User).where(User.username == body.username)):
                raise UserAlreadyExists("El usuario ya existe")
            user = User(username=body.username,
                        password_hash=security.hash_password(body.password.get_secret_value()))
            session.add(user)
            session.flush()
            return {"id": user.id, "username": user.username}
    except IntegrityError:
        raise UserAlreadyExists("El usuario ya existe") from None


@app.post("/auth/login")
def login(body: CredentialsIn):
    """Factor 1. Nunca entrega acceso a recursos: solo un pre_auth_token restringido."""
    return login_flow(body.username, body.password)


@app.post("/auth/2fa/setup")
def setup_2fa(token: SecretStr = Depends(_bearer_token)):
    result = provision_2fa_flow(token)
    return {**result, "qr_code": _qr_data_uri(result["otpauth_uri"])}


@app.post("/auth/2fa/activate")
def activate_2fa(body: CodeIn, token: SecretStr = Depends(_bearer_token)):
    return activate_2fa_flow(token, body.code)


@app.post("/auth/verify-2fa")
def verify_2fa(body: CodeIn, token: SecretStr = Depends(_bearer_token)):
    return verify_2fa_flow(token, body.code, body.method)


@app.get("/api/boveda-secreta")
def boveda_secreta(token: SecretStr = Depends(_bearer_token)):
    claims = security.decode_access_token(token.get_secret_value())
    return {
        "mensaje": f"Bienvenido a la bóveda, {claims['username']}",
        "secreto": "La respuesta es 42",
        "mfa_verified": claims["mfa_verified"],
        "amr": claims["amr"],
    }
