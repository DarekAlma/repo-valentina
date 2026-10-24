import os
import tempfile
from pathlib import Path

import pytest

_DB = Path(tempfile.mkdtemp()) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_DB.as_posix()}"
os.environ["JWT_SECRET"] = "test-secret-with-at-least-32-bytes!!"
os.environ["TOTP_ENCRYPTION_KEY"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture(scope="session", autouse=True)
def prefect_harness():
    # Servidor Prefect temporal: los tests no dependen de `prefect server start`.
    from prefect.testing.utilities import prefect_test_harness

    with prefect_test_harness():
        yield


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.replay_cache import consumed_pre_auth, failed_attempts, used_codes

    for cache in (used_codes, consumed_pre_auth, failed_attempts):
        cache.clear()
    with TestClient(app) as test_client:
        yield test_client
