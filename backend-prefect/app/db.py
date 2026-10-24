"""Persistencia con SQLAlchemy.

SQLite por defecto; para Supabase basta con apuntar DATABASE_URL a su Postgres:
postgresql+psycopg://postgres.<ref>:<password>@<host>:5432/postgres

El esquema coincide con las tablas creadas en Supabase (users, mfa_config,
backup_codes con ids uuid); en SQLite se crean iguales al arrancar.
"""
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, Uuid, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app import config
from app.state_machine import TwoFactorStatus


def utcnow() -> datetime:
    # Las columnas son TIMESTAMP sin zona horaria: se guarda siempre en UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=utcnow)


class TwoFactorConfig(Base):
    __tablename__ = "mfa_config"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), primary_key=True)
    # Semilla cifrada con AES-256-GCM (ver app/crypto.py), nunca en claro.
    secret_encrypted: Mapped[str] = mapped_column("secret_base32", Text)
    status: Mapped[str] = mapped_column(Text, default=TwoFactorStatus.PENDING_VERIFICATION.value)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class BackupCode(Base):
    __tablename__ = "backup_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    code_hash: Mapped[str] = mapped_column(Text)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


_connect_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
