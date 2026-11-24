# Casos de prueba de la regla (semgrep --test semgrep/rules).
# "ruleid" = la regla DEBE reportar la linea siguiente; "ok" = NO debe reportarla.


def bad_fstring_via_variable(conn, q):
    sql = f"SELECT id FROM notes WHERE title LIKE '%{q}%'"
    # ruleid: lab-sqlite-dynamic-sql
    return conn.execute(sql).fetchall()


def bad_fstring_direct(conn, note_id):
    # ruleid: lab-sqlite-dynamic-sql
    return conn.execute(f"SELECT id FROM notes WHERE id = {note_id}").fetchall()


def bad_format(conn, note_id):
    # ruleid: lab-sqlite-dynamic-sql
    return conn.execute("SELECT id FROM notes WHERE id = {}".format(note_id)).fetchall()


def ok_parameterized(conn, q):
    # ok: lab-sqlite-dynamic-sql
    return conn.execute(
        "SELECT id FROM notes WHERE title LIKE ?", (f"%{q}%",)
    ).fetchall()


def ok_constant(conn):
    # ok: lab-sqlite-dynamic-sql
    return conn.execute("SELECT username, role FROM users").fetchall()
