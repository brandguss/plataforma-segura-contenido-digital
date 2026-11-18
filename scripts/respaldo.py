"""
Respaldo cifrado de la información crítica.

    python scripts/respaldo.py

Contenido del respaldo:
    * Copia consistente de la base de datos (API de respaldo de SQLite, segura
      aunque la aplicación esté en ejecución).
    * Todos los productos digitales de productos/.

El paquete .tar.gz se cifra con AES-256-GCM (confidencialidad + integridad)
usando secretos/respaldo.key y se guarda en respaldos/ junto con un manifiesto
JSON (hash SHA-256 del archivo cifrado y conteos de control).

La clave de respaldo NO se incluye en el respaldo: debe custodiarse por separado.
"""
import io
import json
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import cifrar, leer_secreto, sha256_bytes  # noqa: E402
from aplicacion.db import ahora, conectar  # noqa: E402

TABLAS_CONTROL = ("users", "products", "orders", "order_items", "payments", "receipts", "downloads", "security_events")


def conteos(ruta_bd: Path) -> dict:
    conn = conectar(ruta_bd)
    datos = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLAS_CONTROL}  # nombres fijos
    conn.close()
    return datos


def registrar(ruta_bd: Path, evento: str, resultado: str, detalles: str):
    conn = conectar(ruta_bd)
    conn.execute(
        "INSERT INTO security_events (user_id, email, event, result, source, details, created_at)"
        " VALUES (NULL, 'sistema', ?, ?, 'script-local', ?, ?)",
        (evento, resultado, detalles, ahora()),
    )
    conn.commit()
    conn.close()


def crear_respaldo(ruta_bd: Path = None, productos: Path = None, destino: Path = None, clave_ruta: Path = None) -> Path:
    ruta_bd = ruta_bd or Config.DB_PATH
    productos = productos or Config.PRODUCTS_DIR
    destino = destino or Config.BACKUPS_DIR
    clave = leer_secreto(clave_ruta or Config.SECRETS_DIR / Config.BACKUP_KEY)
    destino.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        # 1) Instantánea consistente de la BD
        copia_bd = Path(tmp) / "plataforma.db"
        origen = sqlite3.connect(str(ruta_bd))
        copia = sqlite3.connect(str(copia_bd))
        origen.backup(copia)
        copia.close()
        origen.close()

        # 2) Empaquetar BD + productos
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            tar.add(copia_bd, arcname="base_de_datos/plataforma.db")
            for archivo in sorted(productos.glob("*.pdf")):
                tar.add(archivo, arcname=f"productos/{archivo.name}")
        paquete = buffer.getvalue()

    # 3) Cifrar con AES-256-GCM
    cifrado = cifrar(clave, paquete)
    marca = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    salida = destino / f"respaldo_{marca}.psc"
    salida.write_bytes(cifrado)

    manifiesto = {
        "archivo": salida.name,
        "creado": ahora(),
        "algoritmo": "AES-256-GCM",
        "sha256_cifrado": sha256_bytes(cifrado),
        "tamano_bytes": len(cifrado),
        "productos": len(list(productos.glob("*.pdf"))),
        "conteos": conteos(ruta_bd),
    }
    (destino / f"respaldo_{marca}.json").write_text(json.dumps(manifiesto, indent=2), encoding="utf-8")
    registrar(ruta_bd, "BACKUP_CREATED", "EXITO", f"{salida.name} sha256={manifiesto['sha256_cifrado'][:16]}")
    return salida


if __name__ == "__main__":
    ruta = crear_respaldo()
    manifiesto = json.loads(ruta.with_suffix(".json").read_text(encoding="utf-8"))
    print(f"Respaldo cifrado creado: respaldos/{ruta.name}")
    print(json.dumps(manifiesto, indent=2))
