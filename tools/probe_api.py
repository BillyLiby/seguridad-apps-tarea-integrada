"""Sondeo manual de la API en ejecucion: solicitudes autorizadas, no autorizadas e invalidas.
Uso: python tools/probe_api.py [URL_BASE]     (por defecto http://127.0.0.1:8000)
Solo contra el laboratorio local con datos ficticios."""
import sys

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
CREDS = {"alice": "Alice#Lab2026", "bob": "Bob#Lab2026", "admin": "Admin#Lab2026"}


def token(user):
    r = httpx.post(f"{BASE}/login", json={"username": user, "password": CREDS[user]})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


alice, admin = token("alice"), token("admin")
cases = [
    ("Autorizada: alice lee su nota 1", "GET", "/notes/1", alice, None, None),
    ("No autorizada: alice lee nota 2 (de bob)", "GET", "/notes/2", alice, None, None),
    ("Sin token: GET /notes/1", "GET", "/notes/1", {}, None, None),
    ("Token invalido", "GET", "/notes", {"Authorization": "Bearer abc.def.ghi"}, None, None),
    ("Invalida: titulo de 101 caracteres", "POST", "/notes", alice, {"title": "x" * 101, "content": "c"}, None),
    ("Invalida: campo extra 'owner'", "POST", "/notes", alice, {"title": "t", "content": "c", "owner": "bob"}, None),
    ("Rol: alice en /admin/users", "GET", "/admin/users", alice, None, None),
    ("Rol: admin en /admin/users", "GET", "/admin/users", admin, None, None),
    ("Entrada maliciosa: q=\"x' OR 1=1 --\"", "GET", "/search", alice, None, {"q": "x' OR 1=1 --"}),
]
print(f"Objetivo: {BASE}\n")
print(f"{'Caso':45} {'Metodo':6} {'Ruta':16} Estado")
for name, method, path, headers, body, params in cases:
    r = httpx.request(method, BASE + path, headers=headers, json=body, params=params)
    print(f"{name:45} {method:6} {path:16} {r.status_code}  {r.text[:70]}")
