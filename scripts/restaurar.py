"""
Restauración de un respaldo cifrado.

    python scripts/restaurar.py                         # restaura el respaldo más reciente
    python scripts/restaurar.py respaldos/respaldo_X.psc

Proceso:
    1. Verifica el SHA-256 del archivo contra su manifiesto.
    2. Descifra con AES-256-GCM (si el archivo fue alterado, el descifrado falla).
    3. Reemplaza la base de datos y los productos.
    4. Comprueba conteos de control y el hash de cada producto restaurado.

Detén el servidor antes de restaurar.
"""
import argparse
import io
import json
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import descifrar, leer_secreto, sha256_archivo, sha256_bytes  # noqa: E402
from aplicacion.db import conectar  # noqa: E402
from scripts.respaldo import conteos, registrar  # noqa: E402


def _ultimo(carpeta: Path) -> Path:
    respaldos = sorted(carpeta.glob("respaldo_*.psc"))
    if not respaldos:
        raise FileNotFoundError("No hay respaldos en respaldos/")
    return respaldos[-1]


def restaurar(archivo: Path = None, ruta_bd: Path = None, productos: Path = None, clave_ruta: Path = None) -> dict:
    ruta_bd = ruta_bd or Config.DB_PATH
    productos = productos or Config.PRODUCTS_DIR
    archivo = archivo or _ultimo(Config.BACKUPS_DIR)
    clave = leer_secreto(clave_ruta or Config.SECRETS_DIR / Config.BACKUP_KEY)

    blob = archivo.read_bytes()
    manifiesto_ruta = archivo.with_suffix(".json")
    manifiesto = json.loads(manifiesto_ruta.read_text(encoding="utf-8")) if manifiesto_ruta.exists() else None
    if manifiesto and manifiesto["sha256_cifrado"] != sha256_bytes(blob):
        raise ValueError("El SHA-256 del respaldo no coincide con su manifiesto")

    paquete = descifrar(clave, blob)  # ValueError si fue alterado

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        with tarfile.open(fileobj=io.BytesIO(paquete), mode="r:gz") as tar:
            for miembro in tar.getmembers():
                # Evita rutas maliciosas (../) dentro del paquete
                if miembro.name.startswith("/") or ".." in Path(miembro.name).parts:
                    raise ValueError(f"Ruta no permitida en el respaldo: {miembro.name}")
            try:
                tar.extractall(tmp, filter="data")  # Python 3.12+: filtro seguro integrado
            except TypeError:
                tar.extractall(tmp)  # versiones anteriores (rutas ya validadas arriba)

        ruta_bd.parent.mkdir(parents=True, exist_ok=True)
        for sufijo in ("", "-wal", "-shm"):
            Path(str(ruta_bd) + sufijo).unlink(missing_ok=True)
        shutil.copy2(tmp / "base_de_datos" / "plataforma.db", ruta_bd)

        productos.mkdir(parents=True, exist_ok=True)
        for pdf in (tmp / "productos").glob("*.pdf"):
            shutil.copy2(pdf, productos / pdf.name)

    # Verificación posterior
    restaurado = conteos(ruta_bd)
    conn = conectar(ruta_bd)
    integridad = {
        p["file_name"]: (productos / p["file_name"]).exists()
        and sha256_archivo(productos / p["file_name"]) == p["file_hash"]
        for p in conn.execute("SELECT file_name, file_hash FROM products")
    }
    conn.close()
    resultado = {
        "respaldo": archivo.name,
        "conteos_restaurados": restaurado,
        "conteos_esperados": manifiesto["conteos"] if manifiesto else None,
        "productos_integros": integridad,
        "correcto": all(integridad.values())
        and (manifiesto is None or all(restaurado[t] >= manifiesto["conteos"][t] for t in manifiesto["conteos"])),
    }
    registrar(ruta_bd, "BACKUP_RESTORED", "EXITO" if resultado["correcto"] else "FALLO", archivo.name)
    return resultado


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archivo", nargs="?", type=Path)
    args = parser.parse_args()
    r = restaurar(args.archivo)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["correcto"] else 1)
