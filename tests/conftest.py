"""Fixtures. APP_TARGET elige la version a probar: app_segura (defecto) o app_vulnerable."""
import importlib
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SECRET_KEY", "clave-solo-para-pruebas-de-laboratorio-0123456789")

TARGET = os.environ.get("APP_TARGET", "app_segura")
CREDS = {
    "alice": "Alice#Lab2026",
    "bob": "Bob#Lab2026",
    "admin": "Admin#Lab2026",
}


@pytest.fixture()
def main(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    module = importlib.import_module(f"{TARGET}.main")
    module.init_db()
    return module


@pytest.fixture()
def client(main):
    return TestClient(main.app)


@pytest.fixture()
def auth(client):
    """Devuelve una funcion que entrega cabeceras Authorization para un usuario."""
    def _auth(user: str) -> dict:
        r = client.post("/login", json={"username": user, "password": CREDS[user]})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _auth
