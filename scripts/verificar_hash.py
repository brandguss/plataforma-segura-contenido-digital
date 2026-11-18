"""
Verificación de integridad SHA-256 de los productos.

    python scripts/verificar_hash.py                  # revisa todos los productos contra la BD
    python scripts/verificar_hash.py archivo.pdf      # muestra el SHA-256 de un archivo
"""
import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import sha256_archivo  # noqa: E402
from aplicacion.db import conectar  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archivo", nargs="?", type=Path)
    args = parser.parse_args()

    if args.archivo:
        print(f"{sha256_archivo(args.archivo)}  {args.archivo}")
        sys.exit(0)

    conn = conectar(Config.DB_PATH)
    todo_ok = True
    for p in conn.execute("SELECT id, name, file_name, file_hash FROM products ORDER BY id"):
        ruta = Config.PRODUCTS_DIR / p["file_name"]
        actual = sha256_archivo(ruta) if ruta.exists() else "(no existe)"
        ok = actual == p["file_hash"]
        todo_ok &= ok
        print(f"[{'OK' if ok else 'ALTERADO'}] #{p['id']} {p['name']}")
        print(f"     registrado: {p['file_hash']}")
        print(f"     actual:     {actual}")
    conn.close()
    sys.exit(0 if todo_ok else 1)
