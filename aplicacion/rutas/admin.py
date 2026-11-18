"""
Funciones del rol ADMINISTRADOR: usuarios, roles, sesiones, eventos de
seguridad, operaciones del sistema, configuración de seguridad y detección de
fingerprint en copias sospechosas.

El ADMINISTRADOR nunca ve contraseñas ni hashes: las consultas de usuarios no
seleccionan la columna password_hash, y no hay ruta que exponga claves privadas.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .. import fingerprint
from ..db import ahora, get_db
from ..seguridad import registrar_evento, revocar_sesiones_usuario, roles_requeridos
from ..servicios import clave_fingerprint

bp = Blueprint("admin", __name__, url_prefix="/admin")
solo_admin = roles_requeridos("ADMINISTRADOR")

ROLES = ("CLIENTE", "OPERADOR", "ADMINISTRADOR")

# Límites válidos para cada parámetro de seguridad
LIMITES_CONFIG = {
    "max_failed_logins": (3, 10, "Intentos fallidos antes del bloqueo"),
    "lockout_minutes": (5, 1440, "Minutos de bloqueo temporal"),
    "session_idle_minutes": (5, 240, "Minutos de inactividad antes de cerrar sesión"),
    "password_min_length": (8, 64, "Longitud mínima de contraseña"),
}


def _usuario(user_id):
    fila = get_db().execute(
        "SELECT id, email, name, role, status FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if fila is None:
        abort(404)
    return fila


# ---------------------------------------------------------------------------
# Usuarios y roles
# ---------------------------------------------------------------------------
@bp.route("/usuarios")
@solo_admin
def usuarios():
    filas = get_db().execute(
        "SELECT id, email, name, role, status, failed_attempts, locked_until, created_at, last_login"
        " FROM users ORDER BY id"
    ).fetchall()
    return render_template("admin/usuarios.html", usuarios=filas, roles=ROLES)


@bp.route("/usuario/<int:user_id>/estado", methods=["POST"])
@solo_admin
def estado_usuario(user_id):
    objetivo = _usuario(user_id)
    if objetivo["id"] == g.user["id"]:
        flash("No puedes desactivar tu propia cuenta.", "error")
        return redirect(url_for("admin.usuarios"))
    db = get_db()
    if objetivo["status"] == "ACTIVO":
        db.execute("UPDATE users SET status = 'INACTIVO' WHERE id = ?", (user_id,))
        db.commit()
        revocar_sesiones_usuario(user_id)
        registrar_evento("ACCOUNT_DISABLED", detalles=f"usuario={objetivo['email']}")
        flash("Cuenta desactivada y sesiones revocadas.", "ok")
    else:
        db.execute(
            "UPDATE users SET status = 'ACTIVO', failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,)
        )
        db.commit()
        registrar_evento("ACCOUNT_ENABLED", detalles=f"usuario={objetivo['email']}")
        flash("Cuenta activada.", "ok")
    return redirect(url_for("admin.usuarios"))


@bp.route("/usuario/<int:user_id>/rol", methods=["POST"])
@solo_admin
def rol_usuario(user_id):
    objetivo = _usuario(user_id)
    nuevo = request.form.get("role")
    if nuevo not in ROLES:
        abort(400)
    if objetivo["id"] == g.user["id"]:
        # Separación de responsabilidades: nadie modifica su propio privilegio
        registrar_evento("ROLE_CHANGED", "DENEGADO", detalles="intento de cambiar el rol propio")
        flash("No puedes modificar tu propio rol.", "error")
        return redirect(url_for("admin.usuarios"))
    if nuevo != objetivo["role"]:
        db = get_db()
        db.execute("UPDATE users SET role = ? WHERE id = ?", (nuevo, user_id))
        db.commit()
        revocar_sesiones_usuario(user_id)  # los privilegios nuevos aplican en el siguiente login
        registrar_evento(
            "ROLE_CHANGED", detalles=f"usuario={objetivo['email']} {objetivo['role']}->{nuevo}"
        )
        flash("Rol actualizado.", "ok")
    return redirect(url_for("admin.usuarios"))


# ---------------------------------------------------------------------------
# Sesiones
# ---------------------------------------------------------------------------
@bp.route("/sesiones")
@solo_admin
def sesiones():
    filas = get_db().execute(
        "SELECT s.id, s.ip, s.user_agent, s.created_at, s.last_seen, s.expires_at, u.email, u.role"
        " FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.revoked = 0 AND s.expires_at > ? ORDER BY s.last_seen DESC",
        (ahora(),),
    ).fetchall()
    return render_template("admin/sesiones.html", sesiones=filas)


@bp.route("/sesion/<int:sesion_id>/revocar", methods=["POST"])
@solo_admin
def revocar_sesion(sesion_id):
    db = get_db()
    fila = db.execute(
        "SELECT s.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?", (sesion_id,)
    ).fetchone()
    if fila is None:
        abort(404)
    db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (sesion_id,))
    db.commit()
    registrar_evento("SESSION_REVOKED", detalles=f"sesion={sesion_id} usuario={fila['email']}")
    flash("Sesión revocada.", "ok")
    return redirect(url_for("admin.sesiones"))


# ---------------------------------------------------------------------------
# Eventos y operaciones
# ---------------------------------------------------------------------------
@bp.route("/eventos")
@solo_admin
def eventos():
    evento = (request.args.get("evento") or "").strip().upper()[:40]
    resultado = (request.args.get("resultado") or "").strip().upper()[:10]
    sql = "SELECT * FROM security_events WHERE 1 = 1"
    params = []
    if evento:
        sql += " AND event = ?"
        params.append(evento)
    if resultado:
        sql += " AND result = ?"
        params.append(resultado)
    sql += " ORDER BY id DESC LIMIT 500"
    db = get_db()
    filas = db.execute(sql, params).fetchall()
    tipos = [r["event"] for r in db.execute("SELECT DISTINCT event FROM security_events ORDER BY event")]
    return render_template(
        "admin/eventos.html", eventos=filas, tipos=tipos, filtro_evento=evento, filtro_resultado=resultado
    )


@bp.route("/operaciones")
@solo_admin
def operaciones():
    db = get_db()
    resumen = {
        "usuarios": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "productos": db.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "ordenes": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        "pagadas": db.execute("SELECT COUNT(*) FROM orders WHERE status IN ('PAGADA','COMPLETADA')").fetchone()[0],
        "descargas": db.execute("SELECT COUNT(*) FROM downloads").fetchone()[0],
        "login_fallidos": db.execute("SELECT COUNT(*) FROM security_events WHERE event = 'LOGIN_FAILED'").fetchone()[0],
    }
    pagos = db.execute(
        "SELECT p.order_id, p.transaction_reference, p.amount, p.status, p.created_at, u.email"
        " FROM payments p JOIN orders o ON o.id = p.order_id JOIN users u ON u.id = o.user_id"
        " ORDER BY p.id DESC LIMIT 100"
    ).fetchall()
    descargas = db.execute(
        "SELECT d.order_id, d.product_id, d.fingerprint, d.created_at, d.source_ip, u.email"
        " FROM downloads d JOIN users u ON u.id = d.user_id ORDER BY d.id DESC LIMIT 100"
    ).fetchall()
    return render_template("admin/operaciones.html", resumen=resumen, pagos=pagos, descargas=descargas)


# ---------------------------------------------------------------------------
# Configuración de seguridad
# ---------------------------------------------------------------------------
@bp.route("/configuracion", methods=["GET", "POST"])
@solo_admin
def configuracion():
    db = get_db()
    if request.method == "POST":
        cambios = []
        for clave, (minimo, maximo, _) in LIMITES_CONFIG.items():
            valor = (request.form.get(clave) or "").strip()
            if not valor.isdigit() or not (minimo <= int(valor) <= maximo):
                flash(f"Valor fuera de rango para {clave} ({minimo}-{maximo}).", "error")
                return redirect(url_for("admin.configuracion"))
            cambios.append((clave, valor))
        for clave, valor in cambios:
            db.execute(
                "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (clave, valor, ahora(), g.user["id"]),
            )
        db.commit()
        registrar_evento("SECURITY_SETTINGS_CHANGED", detalles=", ".join(f"{k}={v}" for k, v in cambios))
        flash("Configuración guardada.", "ok")
        return redirect(url_for("admin.configuracion"))
    valores = {r["key"]: r["value"] for r in db.execute("SELECT key, value FROM settings")}
    return render_template("admin/configuracion.html", limites=LIMITES_CONFIG, valores=valores)


# ---------------------------------------------------------------------------
# Detección de fingerprint
# ---------------------------------------------------------------------------
@bp.route("/fingerprint", methods=["GET", "POST"])
@solo_admin
def detectar_fingerprint():
    resultado = None
    descarga = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        datos = archivo.read() if archivo else b""
        if not datos.startswith(b"%PDF-"):
            flash("Sube un archivo PDF.", "error")
            return redirect(url_for("admin.detectar_fingerprint"))
        try:
            resultado = fingerprint.extraer(datos, clave_fingerprint())
        except Exception:  # PDF dañado: no se revela el detalle técnico
            flash("No fue posible analizar el PDF.", "error")
            return redirect(url_for("admin.detectar_fingerprint"))
        if resultado["encontrado"]:
            descarga = get_db().execute(
                "SELECT d.*, u.email, u.name, p.name AS producto FROM downloads d"
                " JOIN users u ON u.id = d.user_id JOIN products p ON p.id = d.product_id"
                " WHERE d.fingerprint = ?",
                (resultado["resultado"]["fingerprint"],),
            ).fetchone()
        registrar_evento(
            "FINGERPRINT_DETECTED",
            "EXITO" if resultado["encontrado"] else "FALLO",
            detalles=resultado["resultado"]["fingerprint"] if resultado["encontrado"] else "sin fingerprint",
        )
    return render_template("admin/fingerprint.html", resultado=resultado, descarga=descarga)
