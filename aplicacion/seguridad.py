"""
Servicios de seguridad de la aplicación:

  * Contraseñas con Argon2id (argon2-cffi maneja la sal automáticamente).
  * Sesiones del lado del servidor: token aleatorio en cookie, solo su SHA-256
    en la BD; expiración por inactividad y absoluta; revocables por el admin.
  * Protección CSRF con token por sesión (o cookie firmada para anónimos).
  * Control de acceso basado en roles con privilegio mínimo.
  * Bitácora de eventos de seguridad.
  * Validación de entradas.
"""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import abort, current_app, g, redirect, request, url_for

from .db import ahora, get_db

# ---------------------------------------------------------------------------
# Contraseñas (Argon2id)
# ---------------------------------------------------------------------------
# Parámetros recomendados por OWASP: 64 MiB de memoria, 3 iteraciones, 4 hilos.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Hash ficticio para igualar el tiempo de respuesta cuando el correo no existe
# (evita enumerar usuarios midiendo cuánto tarda el login).
_HASH_FICTICIO = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verificar_password(hash_guardado: str, password: str) -> bool:
    try:
        return _hasher.verify(hash_guardado, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def necesita_rehash(hash_guardado: str) -> bool:
    return _hasher.check_needs_rehash(hash_guardado)


def simular_verificacion():
    verificar_password(_HASH_FICTICIO, "contraseña-inexistente")


def hash_token(token: str) -> str:
    """Los tokens (sesión, recuperación) se guardan como SHA-256, nunca en claro."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Configuración de seguridad editable por el ADMINISTRADOR
# ---------------------------------------------------------------------------
def get_setting(clave: str) -> int:
    fila = get_db().execute("SELECT value FROM settings WHERE key = ?", (clave,)).fetchone()
    valor = fila["value"] if fila else current_app.config["DEFAULT_SETTINGS"][clave]
    return int(valor)


# ---------------------------------------------------------------------------
# Bitácora de eventos de seguridad
# ---------------------------------------------------------------------------
def ip_origen() -> str:
    # No se confía en X-Forwarded-For: la app no está detrás de un proxy confiable.
    return request.remote_addr or "desconocido"


def registrar_evento(evento, resultado="EXITO", user_id=None, email=None, detalles=None):
    """Inserta un evento en security_events (usuario, evento, fecha, resultado, origen)."""
    if user_id is None and getattr(g, "user", None) is not None:
        user_id, email = g.user["id"], g.user["email"]
    db = get_db()
    db.execute(
        "INSERT INTO security_events (user_id, email, event, result, source, details, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, email, evento, resultado, ip_origen(), detalles, ahora()),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Sesiones del lado del servidor
# ---------------------------------------------------------------------------
def _ahora_dt():
    return datetime.now(timezone.utc)


def _parse(fecha: str) -> datetime:
    return datetime.strptime(fecha, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def crear_sesion(usuario) -> str:
    """Crea una sesión nueva (token nuevo en cada login: evita fijación de sesión)."""
    token = secrets.token_urlsafe(32)
    momento = _ahora_dt()
    expira = momento + timedelta(hours=current_app.config["SESSION_ABSOLUTE_HOURS"])
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, ip, user_agent, created_at,"
        " last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hash_token(token),
            usuario["id"],
            secrets.token_urlsafe(32),
            ip_origen(),
            (request.user_agent.string or "")[:200],
            _fmt(momento),
            _fmt(momento),
            _fmt(expira),
        ),
    )
    db.commit()
    return token


def revocar_sesiones_usuario(user_id: int):
    db = get_db()
    db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,))
    db.commit()


def cargar_usuario():
    """before_request: identifica al usuario a partir de la cookie de sesión."""
    g.user = None
    g.sesion = None
    token = request.cookies.get(current_app.config["AUTH_COOKIE_NAME"])
    if not token:
        return
    db = get_db()
    sesion = db.execute(
        "SELECT s.*, u.email, u.name, u.role, u.status FROM sessions s"
        " JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if sesion is None or sesion["revoked"]:
        return
    momento = _ahora_dt()
    inactividad = timedelta(minutes=get_setting("session_idle_minutes"))
    if momento > _parse(sesion["expires_at"]) or momento - _parse(sesion["last_seen"]) > inactividad:
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (sesion["id"],))
        db.commit()
        return
    if sesion["status"] != "ACTIVO":
        return
    db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (_fmt(momento), sesion["id"]))
    db.commit()
    g.sesion = sesion
    g.user = {
        "id": sesion["user_id"],
        "email": sesion["email"],
        "name": sesion["name"],
        "role": sesion["role"],
    }


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
CSRF_COOKIE = "psc_csrf"


def _firmar_anonimo(valor: str) -> str:
    clave = current_app.config["SECRET_KEY"]
    return hmac.new(clave, valor.encode(), hashlib.sha256).hexdigest()


def csrf_token() -> str:
    """Token que se inserta en cada formulario (disponible en las plantillas)."""
    if g.get("sesion") is not None:
        return g.sesion["csrf_token"]
    # Usuario anónimo: doble envío con cookie firmada (login, registro, recuperación)
    if "csrf_anonimo" not in g:
        valor = request.cookies.get(CSRF_COOKIE)
        if not valor or "." not in valor:
            aleatorio = secrets.token_urlsafe(24)
            valor = f"{aleatorio}.{_firmar_anonimo(aleatorio)}"
            g.csrf_nueva_cookie = valor
        g.csrf_anonimo = valor
    return g.csrf_anonimo


def validar_csrf():
    """before_request: rechaza cualquier POST sin un token CSRF válido."""
    if request.method != "POST":
        return
    enviado = request.form.get("csrf_token", "")
    if g.get("sesion") is not None:
        esperado = g.sesion["csrf_token"]
        valido = hmac.compare_digest(enviado, esperado)
    else:
        cookie = request.cookies.get(CSRF_COOKIE, "")
        valido = False
        if cookie and hmac.compare_digest(enviado, cookie) and "." in cookie:
            aleatorio, firma = cookie.rsplit(".", 1)
            valido = hmac.compare_digest(firma, _firmar_anonimo(aleatorio))
    if not valido:
        registrar_evento("CSRF_REJECTED", "DENEGADO", detalles=request.path)
        abort(400)


# ---------------------------------------------------------------------------
# Control de acceso por roles
# ---------------------------------------------------------------------------
def login_requerido(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("publico.login", next=request.path))
        return vista(*args, **kwargs)

    return envoltura


def roles_requeridos(*roles):
    """Permite la vista solo a los roles indicados; cualquier otro recibe 403."""

    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("publico.login", next=request.path))
            if g.user["role"] not in roles:
                registrar_evento(
                    "ACCESS_DENIED",
                    "DENEGADO",
                    detalles=f"rol={g.user['role']} ruta={request.path}",
                )
                abort(403)
            return vista(*args, **kwargs)

        return envoltura

    return decorador


# ---------------------------------------------------------------------------
# Validación de entradas
# ---------------------------------------------------------------------------
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_PRECIO = re.compile(r"^\d{1,6}(\.\d{1,2})?$")


class ErrorValidacion(ValueError):
    """Error con un mensaje seguro de mostrar al usuario."""


def validar_email(valor: str) -> str:
    valor = (valor or "").strip().lower()
    if not _EMAIL.match(valor):
        raise ErrorValidacion("Correo electrónico no válido.")
    return valor


def validar_texto(valor: str, campo: str, minimo=1, maximo=120) -> str:
    valor = (valor or "").strip()
    if not (minimo <= len(valor) <= maximo):
        raise ErrorValidacion(f"{campo}: debe tener entre {minimo} y {maximo} caracteres.")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in valor):
        raise ErrorValidacion(f"{campo}: contiene caracteres no permitidos.")
    return valor


def validar_password(valor: str) -> str:
    valor = valor or ""
    minimo = get_setting("password_min_length")
    if len(valor) < minimo or len(valor) > 128:
        raise ErrorValidacion(f"La contraseña debe tener entre {minimo} y 128 caracteres.")
    if not (re.search(r"[A-Za-z]", valor) and re.search(r"\d", valor)):
        raise ErrorValidacion("La contraseña debe combinar letras y números.")
    return valor


def validar_precio(valor: str) -> int:
    """Convierte '199.50' a 19950 centavos; rango permitido 0.01 a 999,999.99."""
    valor = (valor or "").strip()
    if not _PRECIO.match(valor):
        raise ErrorValidacion("Precio no válido (ejemplo: 199.50).")
    entero, _, decimales = valor.partition(".")
    centavos = int(entero) * 100 + int((decimales + "00")[:2])
    if centavos <= 0:
        raise ErrorValidacion("El precio debe ser mayor que cero.")
    return centavos


def formato_moneda(centavos: int) -> str:
    return f"${centavos / 100:,.2f} MXN"
