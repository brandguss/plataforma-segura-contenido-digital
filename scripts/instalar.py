"""
Instalación completa en un solo paso (Windows, Linux o macOS):

    python scripts/instalar.py

Pasos:
    1. Claves de la aplicación (firma, fingerprint, respaldo, secreto de sesión)
    2. PKI local: CA, certificado del servidor y certificado no confiable
    3. Productos digitales de prueba (PDF)
    4. Base de datos: esquema + configuración + datos de prueba

Es idempotente: si algo ya existe, se conserva.
"""
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from base_de_datos.crear_bd import crear_bd  # noqa: E402
from base_de_datos.datos_prueba import cargar_datos_prueba  # noqa: E402
from scripts.crear_ca import generar_pki  # noqa: E402
from scripts.generar_claves import generar_claves  # noqa: E402
from scripts.generar_productos import generar_productos  # noqa: E402


def main():
    print("1) Claves de la aplicación")
    generar_claves(Config.SECRETS_DIR, Config.PUBLIC_KEYS_DIR)
    print("2) PKI local (CA + certificados)")
    generar_pki(Config.CERTS_DIR, Config.SECRETS_DIR)
    print("3) Productos digitales")
    productos = generar_productos(Config.PRODUCTS_DIR)
    print("4) Base de datos")
    crear_bd(Config.DB_PATH)
    cargar_datos_prueba(Config.DB_PATH, productos)
    for carpeta in (Config.BACKUPS_DIR, Config.OUTBOX_DIR):
        carpeta.mkdir(parents=True, exist_ok=True)
    print(
        "\nListo. Siguiente paso:\n"
        "  1. Importa certificados/ca.crt como CA raíz de confianza en tu navegador o sistema.\n"
        "  2. Ejecuta:  python -m aplicacion\n"
        "  3. Abre:     https://localhost:8443"
    )


if __name__ == "__main__":
    main()
