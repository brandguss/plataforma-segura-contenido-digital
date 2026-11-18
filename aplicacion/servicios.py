"""
Lógica de negocio que combina BD + criptografía:

  * emitir_comprobante: arma el comprobante de una orden pagada y lo firma.
  * generar_copia_personalizada: valida integridad del original, inserta el
    fingerprint y registra la descarga.
"""
from flask import current_app

from . import fingerprint
from .criptografia import (
    FIRMA_ALGORITMO,
    cargar_privada,
    cargar_publica,
    firmar,
    huella_publica,
    json_canonico,
    leer_secreto,
    sha256_archivo,
    sha256_bytes,
)
from .db import ahora, get_db
from .seguridad import ip_origen, registrar_evento


class ErrorIntegridad(Exception):
    """El archivo original no coincide con el hash registrado."""


def _ruta_privada_firma():
    cfg = current_app.config
    return cfg["SECRETS_DIR"] / cfg["SIGNING_PRIVATE_KEY"]


def ruta_publica_firma():
    cfg = current_app.config
    return cfg["PUBLIC_KEYS_DIR"] / cfg["SIGNING_PUBLIC_KEY"]


def clave_fingerprint() -> bytes:
    cfg = current_app.config
    return leer_secreto(cfg["SECRETS_DIR"] / cfg["FINGERPRINT_KEY"])


# ---------------------------------------------------------------------------
# Comprobantes firmados
# ---------------------------------------------------------------------------
def emitir_comprobante(order_id: int):
    """Genera y firma el comprobante de la orden. Devuelve la fila insertada."""
    db = get_db()
    orden = db.execute(
        "SELECT o.*, u.email, u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (order_id,),
    ).fetchone()
    pago = db.execute(
        "SELECT * FROM payments WHERE order_id = ? AND status = 'APROBADO'", (order_id,)
    ).fetchone()
    items = db.execute(
        "SELECT oi.product_id, oi.price, p.name FROM order_items oi"
        " JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ? ORDER BY oi.product_id",
        (order_id,),
    ).fetchall()

    contenido = {
        "emisor": "Plataforma Segura de Contenido Digital",
        "numero_orden": orden["id"],
        "usuario": {"id": orden["user_id"], "email": orden["email"], "nombre": orden["name"]},
        "productos": [
            {"id": i["product_id"], "nombre": i["name"], "precio_centavos": i["price"]} for i in items
        ],
        "total_centavos": orden["total"],
        "moneda": "MXN",
        "fecha": ahora(),
        "referencia_transaccion": pago["transaction_reference"],
    }

    privada = cargar_privada(_ruta_privada_firma())
    texto = json_canonico(contenido)
    firma = firmar(privada, texto.encode("utf-8"))
    key_id = huella_publica(privada.public_key())

    db.execute(
        "INSERT INTO receipts (order_id, content, signature, algorithm, key_id, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (order_id, texto, firma, FIRMA_ALGORITMO, key_id, ahora()),
    )
    db.commit()
    registrar_evento("SIGNATURE_CREATED", detalles=f"orden={order_id} key_id={key_id}")
    return db.execute("SELECT * FROM receipts WHERE order_id = ?", (order_id,)).fetchone()


def comprobante_exportable(fila_receipt) -> dict:
    """Formato del comprobante que el cliente descarga y puede verificar."""
    import json

    return {
        "contenido": json.loads(fila_receipt["content"]),
        "firma": fila_receipt["signature"],
        "algoritmo": fila_receipt["algorithm"],
        "key_id": fila_receipt["key_id"],
    }


def clave_publica_firma():
    return cargar_publica(ruta_publica_firma())


# ---------------------------------------------------------------------------
# Descarga con fingerprint
# ---------------------------------------------------------------------------
def generar_copia_personalizada(usuario: dict, orden_id: int, producto) -> bytes:
    """Devuelve la copia del PDF con fingerprint y registra la descarga."""
    ruta = current_app.config["PRODUCTS_DIR"] / producto["file_name"]

    # 1) Integridad: el original debe coincidir con el SHA-256 registrado.
    if not ruta.exists() or sha256_archivo(ruta) != producto["file_hash"]:
        registrar_evento(
            "INTEGRITY_FAILED", "FALLO", detalles=f"producto={producto['id']} archivo={producto['file_name']}"
        )
        raise ErrorIntegridad(producto["file_name"])

    # 2) Fingerprint asociado a usuario + orden + producto.
    clave = clave_fingerprint()
    payload = fingerprint.generar_payload(clave, usuario["id"], orden_id, producto["id"])
    copia = fingerprint.insertar(ruta.read_bytes(), payload)
    registrar_evento("FINGERPRINT_CREATED", detalles=f"{payload}")

    # 3) Registro de la descarga.
    db = get_db()
    db.execute(
        "INSERT INTO downloads (user_id, order_id, product_id, fingerprint, copy_hash, source_ip, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (usuario["id"], orden_id, producto["id"], payload, sha256_bytes(copia), ip_origen(), ahora()),
    )
    db.commit()
    registrar_evento("DOWNLOAD", detalles=f"orden={orden_id} producto={producto['id']} fp={payload}")
    return copia
