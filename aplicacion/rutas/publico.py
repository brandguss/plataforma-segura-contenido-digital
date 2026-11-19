"""
Funciones públicas: catálogo, detalle de producto, registro, inicio de sesión,
cierre de sesión y recuperación de contraseña.
"""
import secrets
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from ..db import ahora, get_db
from ..seguridad import (
    ErrorValidacion,
    crear_sesion,
    get_setting,
    hash_password,
    hash_token,
    necesita_rehash,
    registrar_evento,
    revocar_sesiones_usuario,
    simular_verificacion,
    validar_email,
    validar_password,
    validar_texto,
    verificar_password,
)

bp = Blueprint("publico", __name__)

MENSAJE_LOGIN_GENERICO = "Correo o contraseña incorrectos, o la cuenta no está disponible."


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _destino_seguro(destino):
    """Evita redirecciones abiertas: solo rutas internas relativas."""
    if destino and destino.startswith("/") and not destino.startswith("//") and "\\" not in destino:
        return destino
    return None


def _inicio_por_rol(rol):
    return {
        "CLIENTE": url_for("publico.catalogo"),
        "OPERADOR": url_for("operador.productos"),
        "ADMINISTRADOR": url_for("admin.usuarios"),
    }[rol]


# ---------------------------------------------------------------------------
# Catálogo
# ---------------------------------------------------------------------------
@bp.route("/")
def catalogo():
    productos = get_db().execute(
        "SELECT id, name, description, price FROM products WHERE status = 'ACTIVO' ORDER BY id"
    ).fetchall()
    return render_template("publico/catalogo.html", productos=productos)


@bp.route("/producto/<int:producto_id>")
def producto(producto_id):
    fila = get_db().execute(
        "SELECT id, name, description, price, created_at FROM products"
        " WHERE id = ? AND status = 'ACTIVO'",
        (producto_id,),
    ).fetchone()
    if fila is None:
        abort(404)
    return render_template("publico/producto.html", producto=fila)


# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------
@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        try:
            nombre = validar_texto(request.form.get("name"), "Nombre", 2, 80)
            email = validar_email(request.form.get("email"))
            password = validar_password(request.form.get("password"))
            if password != request.form.get("password2"):
                raise ErrorValidacion("Las contraseñas no coinciden.")
        except ErrorValidacion as e:
            flash(str(e), "error")
            return render_template("publico/registro.html"), 400

        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            # Mensaje neutro para no confirmar qué correos están registrados
            flash("No fue posible completar el registro con esos datos.", "error")
            return render_template("publico/registro.html"), 400

        # Todo registro público recibe el rol de menor privilegio: CLIENTE
        cur = db.execute(
            "INSERT INTO users (email, password_hash, name, role, status, created_at)"
            " VALUES (?, ?, ?, 'CLIENTE', 'ACTIVO', ?)",
            (email, hash_password(password), nombre, ahora()),
        )
        db.commit()
        registrar_evento("USER_REGISTERED", user_id=cur.lastrowid, email=email)
        flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
        return redirect(url_for("publico.login"))
    return render_template("publico/registro.html")


# ---------------------------------------------------------------------------
# Inicio y cierre de sesión
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("publico/login.html")

    email_crudo = (request.form.get("email") or "").strip().lower()[:254]
    password = request.form.get("password") or ""
    db = get_db()
    usuario = db.execute("SELECT * FROM users WHERE email = ?", (email_crudo,)).fetchone()

    def fallo(detalle, user_id=None):
        registrar_evento("LOGIN_FAILED", "FALLO", user_id=user_id, email=email_crudo, detalles=detalle)
        flash(MENSAJE_LOGIN_GENERICO, "error")
        return render_template("publico/login.html"), 401

    if usuario is None:
        simular_verificacion()  # mismo tiempo de respuesta que con un usuario real
        return fallo("usuario inexistente")

    momento = datetime.now(timezone.utc)
    if usuario["locked_until"] and usuario["locked_until"] > _fmt(momento):
        simular_verificacion()
        return fallo("cuenta bloqueada temporalmente", usuario["id"])

    if not verificar_password(usuario["password_hash"], password):
        intentos = usuario["failed_attempts"] + 1
        if intentos >= get_setting("max_failed_logins"):
            bloqueo = momento + timedelta(minutes=get_setting("lockout_minutes"))
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (_fmt(bloqueo), usuario["id"]),
            )
            db.commit()
            registrar_evento(
                "ACCOUNT_LOCKED", "EXITO", user_id=usuario["id"], email=usuario["email"],
                detalles=f"bloqueo hasta {_fmt(bloqueo)}",
            )
        else:
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (intentos, usuario["id"]))
            db.commit()
        return fallo(f"contraseña incorrecta (intento {intentos})", usuario["id"])

    if usuario["status"] != "ACTIVO":
        return fallo("cuenta desactivada", usuario["id"])

    # Éxito: reiniciar contador, actualizar hash si cambiaron los parámetros
    nuevo_hash = hash_password(password) if necesita_rehash(usuario["password_hash"]) else usuario["password_hash"]
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?, password_hash = ? WHERE id = ?",
        (ahora(), nuevo_hash, usuario["id"]),
    )
    db.commit()
    token = crear_sesion(usuario)
    registrar_evento("LOGIN_SUCCESS", user_id=usuario["id"], email=usuario["email"])

    destino = _destino_seguro(request.args.get("next")) or _inicio_por_rol(usuario["role"])
    respuesta = make_response(redirect(destino))
    cfg = current_app.config
    respuesta.set_cookie(
        cfg["AUTH_COOKIE_NAME"],
        token,
        max_age=cfg["SESSION_ABSOLUTE_HOURS"] * 3600,
        secure=cfg["SESSION_COOKIE_SECURE"],
        httponly=cfg["SESSION_COOKIE_HTTPONLY"],
        samesite=cfg["SESSION_COOKIE_SAMESITE"],
    )
    return respuesta


@bp.route("/logout", methods=["POST"])
def logout():
    if g.sesion is not None:
        db = get_db()
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.sesion["id"],))
        db.commit()
        registrar_evento("LOGOUT")
    respuesta = make_response(redirect(url_for("publico.catalogo")))
    respuesta.delete_cookie(current_app.config["AUTH_COOKIE_NAME"])
    return respuesta


# ---------------------------------------------------------------------------
# Recuperación de contraseña
# ---------------------------------------------------------------------------
def _enviar_correo_simulado(destinatario, asunto, cuerpo):
    """No se envían correos reales: el mensaje se deja en correo_simulado/."""
    carpeta = current_app.config["OUTBOX_DIR"]
    carpeta.mkdir(parents=True, exist_ok=True)
    nombre = f"{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{secrets.token_hex(3)}.txt"
    (carpeta / nombre).write_text(
        f"Para: {destinatario}\nAsunto: {asunto}\n\n{cuerpo}\n", encoding="utf-8"
    )


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()[:254]
        db = get_db()
        usuario = db.execute(
            "SELECT * FROM users WHERE email = ? AND status = 'ACTIVO'", (email,)
        ).fetchone()
        if usuario:
            token = secrets.token_urlsafe(32)
            minutos = current_app.config["RESET_TOKEN_MINUTES"]
            expira = datetime.now(timezone.utc) + timedelta(minutes=minutos)
            # Solo un token vigente por usuario: los anteriores se invalidan
            db.execute(
                "UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                (ahora(), usuario["id"]),
            )
            db.execute(
                "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (usuario["id"], hash_token(token), _fmt(expira), ahora()),
            )
            db.commit()
            # El enlace se construye con la URL pública configurada, nunca con la cabecera Host
            enlace = current_app.config["PUBLIC_BASE_URL"] + url_for("publico.restablecer", token=token)
            _enviar_correo_simulado(
                usuario["email"],
                "Recuperación de contraseña",
                f"Usa este enlace en los próximos {minutos} minutos (un solo uso):\n{enlace}\n\n"
                "Si no solicitaste el cambio, ignora este mensaje.",
            )
            registrar_evento("PASSWORD_RESET_REQUESTED", user_id=usuario["id"], email=usuario["email"])
        else:
            registrar_evento("PASSWORD_RESET_REQUESTED", "FALLO", email=email, detalles="correo no registrado o inactivo")
        # Misma respuesta exista o no el correo (evita enumeración de usuarios)
        flash("Listo. Si el correo está registrado, pronto te llegará un enlace para restablecer tu contraseña. Estate al pendiente.", "ok")
        return redirect(url_for("publico.login"))
    return render_template("publico/recuperar.html")


def _token_vigente(token):
    return get_db().execute(
        "SELECT pr.*, u.email FROM password_resets pr JOIN users u ON u.id = pr.user_id"
        " WHERE pr.token_hash = ? AND pr.used_at IS NULL AND pr.expires_at > ?",
        (hash_token(token), ahora()),
    ).fetchone()


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
def restablecer(token):
    registro_token = _token_vigente(token[:100])
    if registro_token is None:
        registrar_evento("PASSWORD_RESET", "FALLO", detalles="token inválido, usado o expirado")
        flash("El enlace no es válido o ya expiró.", "error")
        return redirect(url_for("publico.recuperar"))

    if request.method == "POST":
        try:
            password = validar_password(request.form.get("password"))
            if password != request.form.get("password2"):
                raise ErrorValidacion("Las contraseñas no coinciden.")
        except ErrorValidacion as e:
            flash(str(e), "error")
            return render_template("publico/restablecer.html", token=token), 400

        db = get_db()
        db.execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (hash_password(password), registro_token["user_id"]),
        )
        db.execute("UPDATE password_resets SET used_at = ? WHERE id = ?", (ahora(), registro_token["id"]))
        db.commit()
        # Un cambio de contraseña cierra todas las sesiones abiertas del usuario
        revocar_sesiones_usuario(registro_token["user_id"])
        registrar_evento("PASSWORD_RESET", user_id=registro_token["user_id"], email=registro_token["email"])
        flash("Contraseña actualizada. Inicia sesión con tu nueva contraseña.", "ok")
        return redirect(url_for("publico.login"))
    return render_template("publico/restablecer.html", token=token)
