"""!!! VERSION VULNERABLE - SOLO PARA DEMOSTRACION EN LABORATORIO !!!

NO desplegar ni exponer a Internet. Contiene 2 defectos deliberados:
  V1 (BOLA/IDOR, CWE-639): GET /notes/{id} no verifica el propietario.
  V2 (Inyeccion SQL, CWE-89): GET /search concatena la entrada en el SQL.
La version corregida esta en app_segura/.
"""
import hashlib
import hmac
import logging
import os
import sqlite3
import time
from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated

ISSUER = "notas-api-lab"
ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 900  # 15 minutos
PBKDF2_ITERATIONS = 200_000

trace = logging.getLogger("trace")  # trazas locales para 3.3c (no es IAST)


def secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if not key or len(key) < 32:
        raise RuntimeError("SECRET_KEY (>=32 caracteres) es obligatoria")
    return key


def db_path() -> str:
    return os.environ.get("DB_PATH", "notes.db")


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS).hex()


def init_db() -> None:
    """Recrea la base con datos ficticios."""
    path = db_path()
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (username TEXT PRIMARY KEY, salt TEXT NOT NULL,
                            pw_hash TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL,
                            title TEXT NOT NULL, content TEXT NOT NULL);
        """
    )
    seed_users = [
        ("alice", "Alice#Lab2026", "user"),
        ("bob", "Bob#Lab2026", "user"),
        ("admin", "Admin#Lab2026", "admin"),
    ]
    for username, pw, role in seed_users:
        salt = os.urandom(16)
        conn.execute(
            "INSERT INTO users VALUES (?,?,?,?)",
            (username, salt.hex(), hash_password(pw, salt), role),
        )
    conn.executemany(
        "INSERT INTO notes(owner,title,content) VALUES (?,?,?)",
        [
            ("alice", "Plan de Alice", "Contenido privado de Alice"),
            ("bob", "Secreto de Bob", "Contenido privado de Bob"),
            ("alice", "Lista de Alice", "Segunda nota de Alice"),
        ],
    )
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not os.path.exists(db_path()):
        init_db()
    yield


app = FastAPI(title="Notas API (VULNERABLE - LAB)", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)


@app.middleware("http")
async def trace_requests(request: Request, call_next):
    trace.info("[1] entrada HTTP %s %s", request.method, request.url.path)
    response = await call_next(request)
    trace.info("[5] respuesta %s %s -> %s", request.method, request.url.path, response.status_code)
    return response


def db():
    conn = sqlite3.connect(db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def unauthorized(detail: str = "Autenticacion requerida") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    conn: sqlite3.Connection = Depends(db),
) -> dict:
    if creds is None:
        trace.warning("[2] autenticacion: sin credenciales")
        raise unauthorized()
    try:
        payload = jwt.decode(
            creds.credentials,
            secret_key(),
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "sub", "iss"]},
        )
    except jwt.PyJWTError:
        trace.warning("[2] autenticacion: token invalido")
        raise unauthorized("Token invalido o expirado")
    row = conn.execute("SELECT username, role FROM users WHERE username = ?", (payload["sub"],)).fetchone()
    if row is None:
        trace.warning("[2] autenticacion: usuario inexistente")
        raise unauthorized("Token invalido o expirado")
    trace.info("[2] autenticacion OK usuario=%s rol=%s", row["username"], row["role"])
    return {"username": row["username"], "role": row["role"]}


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        trace.warning("[3] autorizacion DENEGADA: %s no es admin", user["username"])
        raise HTTPException(status_code=403, detail="Se requiere rol admin")
    trace.info("[3] autorizacion OK: rol admin")
    return user


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # evita asignacion masiva (p. ej. "owner")
    title: str = Field(min_length=1, max_length=100)
    content: str = Field(max_length=2000)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(data: LoginIn, conn: sqlite3.Connection = Depends(db)):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
    salt = bytes.fromhex(row["salt"]) if row else b"\x00" * 16
    candidate = hash_password(data.password, salt)
    if row is None or not hmac.compare_digest(candidate, row["pw_hash"]):
        raise unauthorized("Credenciales invalidas")
    now = int(time.time())
    token = jwt.encode(
        {"sub": row["username"], "iss": ISSUER, "iat": now, "exp": now + TOKEN_TTL_SECONDS},
        secret_key(),
        algorithm=ALGORITHM,
    )
    return {"access_token": token, "token_type": "bearer"}


@app.get("/notes")
def list_notes(user: dict = Depends(current_user), conn: sqlite3.Connection = Depends(db)):
    rows = conn.execute("SELECT id, title FROM notes WHERE owner = ?", (user["username"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/notes", status_code=201)
def create_note(note: NoteIn, user: dict = Depends(current_user), conn: sqlite3.Connection = Depends(db)):
    cur = conn.execute(
        "INSERT INTO notes(owner, title, content) VALUES (?,?,?)",
        (user["username"], note.title, note.content),
    )
    return {"id": cur.lastrowid, "title": note.title, "content": note.content}


@app.get("/notes/{note_id}")
def get_note(note_id: int, user: dict = Depends(current_user), conn: sqlite3.Connection = Depends(db)):
    row = conn.execute("SELECT id, owner, title, content FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    # DEFECTO V1: falta la verificacion de propietario (BOLA/IDOR)
    return {"id": row["id"], "title": row["title"], "content": row["content"]}


@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, user: dict = Depends(current_user), conn: sqlite3.Connection = Depends(db)):
    row = conn.execute("SELECT owner FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    if row["owner"] != user["username"]:
        raise HTTPException(status_code=403, detail="No tiene permiso sobre este recurso")
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))


@app.get("/search")
def search_notes(
    q: Annotated[str, Query(min_length=1, max_length=200)],
    user: dict = Depends(current_user),
    conn: sqlite3.Connection = Depends(db),
):
    # DEFECTO V2: entrada del cliente concatenada al SQL (inyeccion SQL)
    sql = f"SELECT id, title FROM notes WHERE owner = '{user['username']}' AND title LIKE '%{q}%'"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/users")
def admin_users(_: dict = Depends(require_admin), conn: sqlite3.Connection = Depends(db)):
    rows = conn.execute("SELECT username, role FROM users").fetchall()
    return [dict(r) for r in rows]
