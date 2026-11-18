"""
Acceso a la base de datos relacional (SQLite).

Todas las consultas del proyecto usan parámetros (?) para evitar inyección SQL;
nunca se concatenan valores del usuario dentro de una sentencia.
"""
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g


def ahora():
    """Fecha/hora actual en UTC con formato ISO 8601 (se ordena bien como texto)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def conectar(ruta):
    """Abre una conexión con claves foráneas activas y filas tipo diccionario."""
    conn = sqlite3.connect(str(ruta), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """Conexión reutilizable durante una misma petición HTTP."""
    if "db" not in g:
        g.db = conectar(current_app.config["DB_PATH"])
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def crear_esquema(ruta_bd, ruta_schema):
    """Crea todas las tablas a partir de schema.sql (idempotente)."""
    conn = conectar(ruta_bd)
    with open(ruta_schema, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def init_app(app):
    app.teardown_appcontext(close_db)
