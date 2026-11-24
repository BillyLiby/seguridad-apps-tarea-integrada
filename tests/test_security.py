"""Pruebas de seguridad. IDs de datos semilla: nota 1 y 3 = alice, nota 2 = bob."""
import logging

import jwt


# ---- T1: acceso legitimo a recurso propio -------------------------------------
def test_t1_owner_reads_own_note(client, auth):
    """Entrada: alice (token valido) pide la nota 1 (suya). Esperado: 200 y su contenido."""
    r = client.get("/notes/1", headers=auth("alice"))
    assert r.status_code == 200
    assert r.json()["title"] == "Plan de Alice"


# ---- T2: denegacion de acceso a recurso ajeno (BOLA/IDOR) ---------------------
def test_t2_user_cannot_read_other_users_note(client, auth):
    """Entrada: alice pide la nota 2 (de bob). Esperado: 403 y sin contenido de bob."""
    r = client.get("/notes/2", headers=auth("alice"))
    assert r.status_code == 403
    assert "Bob" not in r.text


# ---- T3: solicitud sin autenticacion valida -----------------------------------
def test_t3_missing_token_is_rejected(client):
    """Entrada: sin cabecera Authorization. Esperado: 401."""
    assert client.get("/notes/1").status_code == 401


def test_t3b_tampered_and_unsigned_tokens_are_rejected(client, main):
    """Entrada: token con firma incorrecta y token alg=none. Esperado: 401 en ambos."""
    forged = jwt.encode({"sub": "admin", "iss": "notas-api-lab", "exp": 9999999999},
                        "otra-clave-cualquiera-de-32-bytes-minimo!!", algorithm="HS256")
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_tok = jwt.encode({"sub": "admin", "iss": "notas-api-lab", "exp": 9999999999}, key=None, algorithm="none")
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {none_tok}"}).status_code == 401


# ---- T4: validacion de entrada inesperada -------------------------------------
def test_t4_unexpected_input_is_rejected(client, auth):
    """Entrada: titulo de 101 caracteres, y campo extra 'owner'. Esperado: 422 en ambos."""
    h = auth("alice")
    assert client.post("/notes", json={"title": "x" * 101, "content": "c"}, headers=h).status_code == 422
    assert client.post("/notes", json={"title": "ok", "content": "c", "owner": "bob"}, headers=h).status_code == 422


# ---- T5: restriccion por rol ---------------------------------------------------
def test_t5_admin_endpoint_restricted_by_role(client, auth):
    """Entrada: /admin/users con usuario normal y con admin. Esperado: 403 y 200."""
    assert client.get("/admin/users", headers=auth("alice")).status_code == 403
    r = client.get("/admin/users", headers=auth("admin"))
    assert r.status_code == 200
    assert {u["username"] for u in r.json()} == {"alice", "bob", "admin"}


# ---- T6: inyeccion SQL (negativa) y busqueda legitima (positiva) ---------------
def test_t6_sql_injection_does_not_leak_other_users_data(client, auth):
    """Entrada: q = "x' OR 1=1 --". Esperado: no aparece la nota de bob."""
    r = client.get("/search", params={"q": "x' OR 1=1 --"}, headers=auth("alice"))
    assert "Secreto de Bob" not in r.text


def test_t6b_legitimate_search_still_works(client, auth):
    """Entrada: q = 'Plan'. Esperado: 200 con solo la nota 1 de alice."""
    r = client.get("/search", params={"q": "Plan"}, headers=auth("alice"))
    assert r.status_code == 200
    assert [n["id"] for n in r.json()] == [1]


# ---- T7: traza del recorrido interno de una solicitud (3.3c) -------------------
def test_t7_request_flow_trace(client, auth, caplog):
    """Registra el recorrido: entrada HTTP -> autenticacion -> autorizacion por objeto -> respuesta."""
    headers = auth("alice")
    with caplog.at_level(logging.INFO, logger="trace"):
        client.get("/notes/2", headers=headers)
    flow = [rec.getMessage() for rec in caplog.records if rec.name == "trace"]
    print("\n".join(flow))
    assert any("[1] entrada HTTP GET /notes/2" in m for m in flow)
    assert any("[2] autenticacion OK usuario=alice" in m for m in flow)
    assert any("[4] autorizacion por objeto DENEGADA" in m for m in flow)
    assert any("[5] respuesta GET /notes/2 -> 403" in m for m in flow)


# ---- T8: token expirado (R5 / ASVS 7.3.2) ---------------------------------------
def test_t8_expired_token_is_rejected(client):
    """Entrada: token de alice correctamente firmado pero con exp en el pasado. Esperado: 401."""
    import os
    import time
    expired = jwt.encode(
        {"sub": "alice", "iss": "notas-api-lab", "iat": int(time.time()) - 2000, "exp": int(time.time()) - 1000},
        os.environ["SECRET_KEY"], algorithm="HS256",
    )
    assert client.get("/notes", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
