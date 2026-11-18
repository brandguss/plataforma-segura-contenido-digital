"""
Script de creación de la base de datos.

    python base_de_datos/crear_bd.py            # crea las tablas si no existen
    python base_de_datos/crear_bd.py --reiniciar  # BORRA la BD y la crea de nuevo (pide confirmación)

Crea todas las tablas definidas en schema.sql e inserta la configuración de
seguridad por defecto.
"""
import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.db import ahora, conectar, crear_esquema  # noqa: E402


def crear_bd(ruta_bd: Path, reiniciar=False):
    ruta_bd.parent.mkdir(parents=True, exist_ok=True)
    if reiniciar and ruta_bd.exists():
        ruta_bd.unlink()
        print(f"  [-] Base de datos eliminada: {ruta_bd.name}")
    crear_esquema(ruta_bd, Config.SCHEMA_PATH)
    conn = conectar(ruta_bd)
    for clave, valor in Config.DEFAULT_SETTINGS.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (clave, valor, ahora())
        )
    conn.commit()
    tablas = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    conn.close()
    print(f"  [+] Esquema listo ({len(tablas)} tablas): {', '.join(tablas)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reiniciar", action="store_true")
    args = parser.parse_args()
    if args.reiniciar and input("Esto borra TODOS los datos. Escribe SI para continuar: ").strip() != "SI":
        sys.exit("Cancelado.")
    crear_bd(Config.DB_PATH, args.reiniciar)
