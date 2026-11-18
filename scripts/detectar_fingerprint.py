"""
Extrae el fingerprint de una copia sospechosa e identifica usuario y orden.

    python scripts/detectar_fingerprint.py ruta/al/archivo.pdf

Muestra las capas en las que se encontró el identificador, valida su HMAC y
lo busca en la tabla downloads.
"""
import argparse
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion import fingerprint  # noqa: E402
from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import leer_secreto  # noqa: E402
from aplicacion.db import conectar  # noqa: E402


def detectar(pdf: Path, ruta_bd: Path = None, clave_ruta: Path = None) -> dict:
    clave = leer_secreto(clave_ruta or Config.SECRETS_DIR / Config.FINGERPRINT_KEY)
    analisis = fingerprint.extraer(pdf.read_bytes(), clave)
    registro = None
    if analisis["encontrado"]:
        conn = conectar(ruta_bd or Config.DB_PATH)
        fila = conn.execute(
            "SELECT d.order_id, d.product_id, d.created_at, d.source_ip, u.id AS user_id, u.email, u.name"
            " FROM downloads d JOIN users u ON u.id = d.user_id WHERE d.fingerprint = ?",
            (analisis["resultado"]["fingerprint"],),
        ).fetchone()
        conn.close()
        registro = dict(fila) if fila else None
    return {"analisis": analisis, "descarga_registrada": registro}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pdf", type=Path)
    args = parser.parse_args()
    r = detectar(args.pdf)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["analisis"]["encontrado"] else 1)
