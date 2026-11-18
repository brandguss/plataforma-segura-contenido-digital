"""
Funciones del rol CLIENTE: perfil, carrito, órdenes, pago simulado,
comprobantes firmados, verificación de firma y descargas con fingerprint.

Regla clave (control de acceso a nivel de objeto): toda consulta de órdenes,
comprobantes y descargas filtra por user_id = usuario autenticado.
"""
import json
import re
import secrets

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..criptografia import verificar_comprobante
from ..db import ahora, get_db
from ..seguridad import (
    ErrorValidacion,
    hash_password,
    registrar_evento,
    revocar_sesiones_usuario,
    roles_requeridos,
    validar_password,
    validar_texto,
    verificar_password,
)
from ..servicios import (
    ErrorIntegridad,
    clave_publica_firma,
    comprobante_exportable,
    emitir_comprobante,
    generar_copia_personalizada,
)

bp = Blueprint("cliente", __name__, url_prefix="/cliente")
solo_cliente = roles_requeridos("CLIENTE")

ESTADOS_DESCARGABLES = ("PAGADA", "COMPLETADA")


def _orden_propia(orden_id):
    """Devuelve la orden solo si pertenece al usuario; si no, 403 y evento."""
    orden = get_db().execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?", (orden_id, g.user["id"])
    ).fetchone()
    if orden is None:
        registrar_evento("ACCESS_DENIED", "DENEGADO", detalles=f"orden ajena o inexistente id={orden_id}")
        abort(403)
    return orden


# ---------------------------------------------------------------------------
# Perfil
# ---------------------------------------------------------------------------
@bp.route("/perfil", methods=["GET", "POST"])
@solo_cliente
def perfil():
    db = get_db()
    if request.method == "POST":
        accion = request.form.get("accion")
        try:
            if accion == "datos":
                nombre = validar_texto(request.form.get("name"), "Nombre", 2, 80)
                db.execute("UPDATE users SET name = ? WHERE id = ?", (nombre, g.user["id"]))
                db.commit()
                registrar_evento("PROFILE_UPDATED")
                flash("Perfil actualizado.", "ok")
            elif accion == "password":
                fila = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
                if not verificar_password(fila["password_hash"], request.form.get("actual") or ""):
                    registrar_evento("PASSWORD_CHANGED", "FALLO", detalles="contraseña actual incorrecta")
                    raise ErrorValidacion("La contraseña actual no es correcta.")
                nueva = validar_password(request.form.get("password"))
                if nueva != request.form.get("password2"):
                    raise ErrorValidacion("Las contraseñas no coinciden.")
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(nueva), g.user["id"]))
                db.commit()
                revocar_sesiones_usuario(g.user["id"])
                registrar_evento("PASSWORD_CHANGED")
                flash("Contraseña cambiada. Inicia sesión de nuevo.", "ok")
                return redirect(url_for("publico.login"))
            else:
                abort(400)
        except ErrorValidacion as e:
            flash(str(e), "error")
        return redirect(url_for("cliente.perfil"))
    datos = db.execute(
        "SELECT email, name, created_at, last_login FROM users WHERE id = ?", (g.user["id"],)
    ).fetchone()
    return render_template("cliente/perfil.html", datos=datos)


# ---------------------------------------------------------------------------
# Carrito
# ---------------------------------------------------------------------------
@bp.route("/carrito")
@solo_cliente
def carrito():
    items = get_db().execute(
        "SELECT p.id, p.name, p.price FROM cart_items c JOIN products p ON p.id = c.product_id"
        " WHERE c.user_id = ? AND p.status = 'ACTIVO' ORDER BY c.added_at",
        (g.user["id"],),
    ).fetchall()
    total = sum(i["price"] for i in items)
    return render_template("cliente/carrito.html", items=items, total=total)


@bp.route("/carrito/agregar/<int:producto_id>", methods=["POST"])
@solo_cliente
def agregar(producto_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM products WHERE id = ? AND status = 'ACTIVO'", (producto_id,)).fetchone():
        abort(404)
    db.execute(
        "INSERT OR IGNORE INTO cart_items (user_id, product_id, added_at) VALUES (?, ?, ?)",
        (g.user["id"], producto_id, ahora()),
    )
    db.commit()
    flash("Producto agregado al carrito.", "ok")
    return redirect(url_for("cliente.carrito"))


@bp.route("/carrito/quitar/<int:producto_id>", methods=["POST"])
@solo_cliente
def quitar(producto_id):
    db = get_db()
    db.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (g.user["id"], producto_id))
    db.commit()
    return redirect(url_for("cliente.carrito"))


# ---------------------------------------------------------------------------
# Órdenes
# ---------------------------------------------------------------------------
@bp.route("/checkout", methods=["POST"])
@solo_cliente
def checkout():
    db = get_db()
    # Los precios se toman de la BD en este momento, nunca del formulario
    items = db.execute(
        "SELECT p.id, p.price FROM cart_items c JOIN products p ON p.id = c.product_id"
        " WHERE c.user_id = ? AND p.status = 'ACTIVO'",
        (g.user["id"],),
    ).fetchall()
    if not items:
        flash("Tu carrito está vacío.", "error")
        return redirect(url_for("cliente.carrito"))
    total = sum(i["price"] for i in items)
    cur = db.execute(
        "INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, 'PENDIENTE', ?)",
        (g.user["id"], total, ahora()),
    )
    orden_id = cur.lastrowid
    db.executemany(
        "INSERT INTO order_items (order_id, product_id, price) VALUES (?, ?, ?)",
        [(orden_id, i["id"], i["price"]) for i in items],
    )
    db.execute("DELETE FROM cart_items WHERE user_id = ?", (g.user["id"],))
    db.commit()
    registrar_evento("ORDER_CREATED", detalles=f"orden={orden_id} total={total}")
    return redirect(url_for("cliente.pagar", orden_id=orden_id))


@bp.route("/ordenes")
@solo_cliente
def ordenes():
    filas = get_db().execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)
    ).fetchall()
    return render_template("cliente/ordenes.html", ordenes=filas)


@bp.route("/orden/<int:orden_id>")
@solo_cliente
def orden(orden_id):
    orden = _orden_propia(orden_id)
    db = get_db()
    items = db.execute(
        "SELECT oi.product_id, oi.price, p.name FROM order_items oi JOIN products p ON p.id = oi.product_id"
        " WHERE oi.order_id = ?",
        (orden_id,),
    ).fetchall()
    pagos = db.execute("SELECT * FROM payments WHERE order_id = ? ORDER BY id", (orden_id,)).fetchall()
    comprobante = db.execute("SELECT id FROM receipts WHERE order_id = ?", (orden_id,)).fetchone()
    return render_template(
        "cliente/orden.html",
        orden=orden,
        items=items,
        pagos=pagos,
        comprobante=comprobante,
        descargable=orden["status"] in ESTADOS_DESCARGABLES,
    )


# ---------------------------------------------------------------------------
# Pago simulado
# ---------------------------------------------------------------------------
@bp.route("/orden/<int:orden_id>/pagar", methods=["GET", "POST"])
@solo_cliente
def pagar(orden_id):
    orden = _orden_propia(orden_id)
    if orden["status"] not in ("PENDIENTE", "RECHAZADA"):
        flash("Esta orden ya no admite pagos.", "error")
        return redirect(url_for("cliente.orden", orden_id=orden_id))

    if request.method == "POST":
        # El número capturado solo se usa para decidir el resultado simulado;
        # NUNCA se guarda en la BD ni en la bitácora.
        numero = re.sub(r"[\s-]", "", request.form.get("tarjeta_prueba") or "")
        cfg = current_app.config
        if numero == cfg["TEST_CARD_APPROVED"]:
            estado = "APROBADO"
        elif numero == cfg["TEST_CARD_DECLINED"]:
            estado = "RECHAZADO"
        else:
            flash("Usa una de las tarjetas de prueba indicadas. No se aceptan datos reales.", "error")
            return render_template("cliente/pagar.html", orden=orden), 400

        db = get_db()
        referencia = f"SIM-{secrets.token_hex(8).upper()}"
        db.execute(
            "INSERT INTO payments (order_id, transaction_reference, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (orden_id, referencia, orden["total"], estado, ahora()),
        )
        nuevo_estado = "PAGADA" if estado == "APROBADO" else "RECHAZADA"
        db.execute("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?", (nuevo_estado, ahora(), orden_id))
        db.commit()

        if estado == "APROBADO":
            registrar_evento("PAYMENT_APPROVED", detalles=f"orden={orden_id} ref={referencia}")
            emitir_comprobante(orden_id)
            flash("Pago aprobado. Tu comprobante firmado está disponible.", "ok")
        else:
            registrar_evento("PAYMENT_DECLINED", "FALLO", detalles=f"orden={orden_id} ref={referencia}")
            flash("Pago rechazado (simulado). Puedes intentarlo de nuevo.", "error")
        return redirect(url_for("cliente.orden", orden_id=orden_id))
    return render_template("cliente/pagar.html", orden=orden)


# ---------------------------------------------------------------------------
# Comprobantes y verificación de firma
# ---------------------------------------------------------------------------
def _comprobante_propio(orden_id):
    _orden_propia(orden_id)
    fila = get_db().execute("SELECT * FROM receipts WHERE order_id = ?", (orden_id,)).fetchone()
    if fila is None:
        abort(404)
    return fila


@bp.route("/orden/<int:orden_id>/comprobante")
@solo_cliente
def comprobante(orden_id):
    fila = _comprobante_propio(orden_id)
    exportable = comprobante_exportable(fila)
    valido = verificar_comprobante(clave_publica_firma(), exportable)
    return render_template(
        "cliente/comprobante.html",
        orden_id=orden_id,
        c=exportable,
        valido=valido,
        json_texto=json.dumps(exportable, ensure_ascii=False, indent=2),
    )


@bp.route("/orden/<int:orden_id>/comprobante.json")
@solo_cliente
def comprobante_json(orden_id):
    exportable = comprobante_exportable(_comprobante_propio(orden_id))
    return Response(
        json.dumps(exportable, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="comprobante_orden_{orden_id}.json"'},
    )


@bp.route("/verificar", methods=["GET", "POST"])
@solo_cliente
def verificar():
    resultado = None
    texto = ""
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if archivo and archivo.filename:
            texto = archivo.read(200_000).decode("utf-8", errors="replace")
        else:
            texto = (request.form.get("comprobante") or "")[:200_000]
        try:
            datos = json.loads(texto)
            resultado = "VALIDA" if verificar_comprobante(clave_publica_firma(), datos) else "INVALIDA"
        except (json.JSONDecodeError, UnicodeDecodeError):
            resultado = "FORMATO"
        registrar_evento(
            "SIGNATURE_VERIFIED", "EXITO" if resultado == "VALIDA" else "FALLO", detalles=f"resultado={resultado}"
        )
    return render_template("cliente/verificar.html", resultado=resultado, texto=texto)


# ---------------------------------------------------------------------------
# Descarga con fingerprint
# ---------------------------------------------------------------------------
@bp.route("/descargar/<int:orden_id>/<int:producto_id>")
@solo_cliente
def descargar(orden_id, producto_id):
    db = get_db()
    # Una sola consulta comprueba: orden propia + pagada + producto incluido
    fila = db.execute(
        "SELECT p.* FROM orders o"
        " JOIN order_items oi ON oi.order_id = o.id"
        " JOIN products p ON p.id = oi.product_id"
        " WHERE o.id = ? AND o.user_id = ? AND oi.product_id = ? AND o.status IN ('PAGADA', 'COMPLETADA')",
        (orden_id, g.user["id"], producto_id),
    ).fetchone()
    if fila is None:
        registrar_evento(
            "DOWNLOAD", "DENEGADO", detalles=f"producto no adquirido orden={orden_id} producto={producto_id}"
        )
        abort(403)
    try:
        copia = generar_copia_personalizada(g.user, orden_id, fila)
    except ErrorIntegridad:
        flash("El archivo no superó la verificación de integridad. Se notificó al equipo.", "error")
        return redirect(url_for("cliente.orden", orden_id=orden_id))
    nombre = f"orden{orden_id}_producto{producto_id}.pdf"
    return Response(
        copia,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{nombre}"'},
    )
