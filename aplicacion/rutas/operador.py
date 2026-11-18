"""
Funciones del rol OPERADOR: catálogo (alta, edición, precio, activar/desactivar)
y procesamiento de órdenes.

El OPERADOR no tiene rutas para roles, usuarios, contraseñas, claves privadas
ni para borrar eventos de seguridad (además, la BD lo impide con triggers).
"""
import io
import secrets

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from ..criptografia import sha256_archivo, sha256_bytes
from ..db import ahora, get_db
from ..seguridad import ErrorValidacion, registrar_evento, roles_requeridos, validar_precio, validar_texto

bp = Blueprint("operador", __name__, url_prefix="/operador")
solo_operador = roles_requeridos("OPERADOR")

# Transiciones de estado permitidas al OPERADOR
TRANSICIONES = {
    "PENDIENTE": ["CANCELADA"],
    "RECHAZADA": ["CANCELADA"],
    "PAGADA": ["COMPLETADA"],
}


def _validar_pdf(archivo) -> bytes:
    """Acepta solo PDFs reales: firma %PDF- y estructura legible por pypdf."""
    if archivo is None or not archivo.filename:
        raise ErrorValidacion("Selecciona un archivo PDF.")
    datos = archivo.read()
    if not datos.startswith(b"%PDF-"):
        raise ErrorValidacion("El archivo no es un PDF válido.")
    try:
        if len(PdfReader(io.BytesIO(datos)).pages) == 0:
            raise ErrorValidacion("El PDF no contiene páginas.")
    except PdfReadError as exc:
        raise ErrorValidacion("El PDF está dañado o no se puede leer.") from exc
    return datos


def _guardar_pdf(datos: bytes) -> tuple:
    """Nombre interno aleatorio: el nombre original del usuario nunca toca el disco."""
    nombre = f"prod_{secrets.token_hex(8)}.pdf"
    ruta = current_app.config["PRODUCTS_DIR"] / nombre
    ruta.write_bytes(datos)
    return nombre, sha256_bytes(datos)


def _producto(producto_id):
    fila = get_db().execute("SELECT * FROM products WHERE id = ?", (producto_id,)).fetchone()
    if fila is None:
        abort(404)
    return fila


# ---------------------------------------------------------------------------
# Productos
# ---------------------------------------------------------------------------
@bp.route("/productos")
@solo_operador
def productos():
    filas = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    carpeta = current_app.config["PRODUCTS_DIR"]
    integridad = {}
    for p in filas:
        ruta = carpeta / p["file_name"]
        integridad[p["id"]] = ruta.exists() and sha256_archivo(ruta) == p["file_hash"]
    return render_template("operador/productos.html", productos=filas, integridad=integridad)


@bp.route("/productos/nuevo", methods=["GET", "POST"])
@solo_operador
def nuevo_producto():
    if request.method == "POST":
        try:
            nombre = validar_texto(request.form.get("name"), "Nombre", 3, 120)
            descripcion = validar_texto(request.form.get("description"), "Descripción", 10, 2000)
            precio = validar_precio(request.form.get("price"))
            datos = _validar_pdf(request.files.get("archivo"))
        except ErrorValidacion as e:
            flash(str(e), "error")
            return render_template("operador/producto_form.html", producto=None), 400
        archivo, sha = _guardar_pdf(datos)
        db = get_db()
        cur = db.execute(
            "INSERT INTO products (name, description, price, file_name, file_hash, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, 'ACTIVO', ?)",
            (nombre, descripcion, precio, archivo, sha, ahora()),
        )
        db.commit()
        registrar_evento("PRODUCT_CREATED", detalles=f"producto={cur.lastrowid} sha256={sha}")
        flash("Producto registrado.", "ok")
        return redirect(url_for("operador.productos"))
    return render_template("operador/producto_form.html", producto=None)


@bp.route("/productos/<int:producto_id>/editar", methods=["GET", "POST"])
@solo_operador
def editar_producto(producto_id):
    actual = _producto(producto_id)
    if request.method == "POST":
        try:
            nombre = validar_texto(request.form.get("name"), "Nombre", 3, 120)
            descripcion = validar_texto(request.form.get("description"), "Descripción", 10, 2000)
            precio = validar_precio(request.form.get("price"))
            archivo = request.files.get("archivo")
            nuevo_pdf = _validar_pdf(archivo) if archivo and archivo.filename else None
        except ErrorValidacion as e:
            flash(str(e), "error")
            return render_template("operador/producto_form.html", producto=actual), 400

        db = get_db()
        file_name, file_hash = actual["file_name"], actual["file_hash"]
        if nuevo_pdf is not None:
            file_name, file_hash = _guardar_pdf(nuevo_pdf)
        db.execute(
            "UPDATE products SET name = ?, description = ?, price = ?, file_name = ?, file_hash = ?, updated_at = ?"
            " WHERE id = ?",
            (nombre, descripcion, precio, file_name, file_hash, ahora(), producto_id),
        )
        db.commit()
        if precio != actual["price"]:
            registrar_evento(
                "PRICE_CHANGED", detalles=f"producto={producto_id} anterior={actual['price']} nuevo={precio}"
            )
        registrar_evento(
            "PRODUCT_UPDATED",
            detalles=f"producto={producto_id}" + (f" nuevo_sha256={file_hash}" if nuevo_pdf else ""),
        )
        flash("Producto actualizado.", "ok")
        return redirect(url_for("operador.productos"))
    return render_template("operador/producto_form.html", producto=actual)


@bp.route("/productos/<int:producto_id>/estado", methods=["POST"])
@solo_operador
def estado_producto(producto_id):
    actual = _producto(producto_id)
    nuevo = "INACTIVO" if actual["status"] == "ACTIVO" else "ACTIVO"
    db = get_db()
    db.execute("UPDATE products SET status = ?, updated_at = ? WHERE id = ?", (nuevo, ahora(), producto_id))
    db.commit()
    registrar_evento("PRODUCT_STATUS_CHANGED", detalles=f"producto={producto_id} estado={nuevo}")
    flash(f"Producto {nuevo.lower()}.", "ok")
    return redirect(url_for("operador.productos"))


# ---------------------------------------------------------------------------
# Órdenes
# ---------------------------------------------------------------------------
@bp.route("/ordenes")
@solo_operador
def ordenes():
    filas = get_db().execute(
        "SELECT o.*, u.email FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id DESC"
    ).fetchall()
    return render_template("operador/ordenes.html", ordenes=filas)


@bp.route("/orden/<int:orden_id>", methods=["GET", "POST"])
@solo_operador
def orden(orden_id):
    db = get_db()
    orden = db.execute(
        "SELECT o.*, u.email, u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (orden_id,),
    ).fetchone()
    if orden is None:
        abort(404)
    if request.method == "POST":
        nuevo = request.form.get("status")
        if nuevo not in TRANSICIONES.get(orden["status"], []):
            flash("Cambio de estado no permitido.", "error")
        else:
            db.execute("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?", (nuevo, ahora(), orden_id))
            db.commit()
            registrar_evento(
                "ORDER_STATUS_CHANGED", detalles=f"orden={orden_id} {orden['status']}->{nuevo}"
            )
            flash("Estado actualizado.", "ok")
        return redirect(url_for("operador.orden", orden_id=orden_id))
    items = db.execute(
        "SELECT oi.*, p.name FROM order_items oi JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?",
        (orden_id,),
    ).fetchall()
    pagos = db.execute(
        "SELECT transaction_reference, amount, status, created_at FROM payments WHERE order_id = ?", (orden_id,)
    ).fetchall()
    return render_template(
        "operador/orden.html",
        orden=orden,
        items=items,
        pagos=pagos,
        transiciones=TRANSICIONES.get(orden["status"], []),
    )
