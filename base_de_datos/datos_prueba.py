"""
Datos de prueba: usuarios ficticios (uno por rol + un segundo cliente) y los
productos generados por scripts/generar_productos.py.

    python base_de_datos/datos_prueba.py

Solo inserta si la tabla correspondiente está vacía. Las contraseñas se guardan
exclusivamente como hash Argon2id. Ningún dato corresponde a personas reales.
"""
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import sha256_archivo  # noqa: E402
from aplicacion.db import ahora, conectar  # noqa: E402
from aplicacion.seguridad import hash_password  # noqa: E402

# Cuentas de demostración (también documentadas en el README)
USUARIOS_PRUEBA = [
    ("admin@demo.local", "Admin#2026Seguro", "Ana Administradora", "ADMINISTRADOR"),
    ("operador@demo.local", "Operador#2026Seguro", "Omar Operador", "OPERADOR"),
    ("cliente1@demo.local", "Cliente#2026Uno", "Carla Cliente", "CLIENTE"),
    ("cliente2@demo.local", "Cliente#2026Dos", "Carlos Cliente", "CLIENTE"),
]


def cargar_datos_prueba(ruta_bd: Path, productos: list):
    conn = conectar(ruta_bd)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for email, password, nombre, rol in USUARIOS_PRUEBA:
            conn.execute(
                "INSERT INTO users (email, password_hash, name, role, status, created_at) VALUES (?, ?, ?, ?, 'ACTIVO', ?)",
                (email, hash_password(password), nombre, rol, ahora()),
            )
        print(f"  [+] {len(USUARIOS_PRUEBA)} usuarios de prueba creados")
    else:
        print("  [=] Ya existen usuarios, no se insertan los de prueba")

    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        for p in productos:
            ruta = Config.PRODUCTS_DIR / p["archivo"]
            conn.execute(
                "INSERT INTO products (name, description, price, file_name, file_hash, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'ACTIVO', ?)",
                (p["nombre"], p["descripcion"], p["precio"], p["archivo"], sha256_archivo(ruta), ahora()),
            )
        print(f"  [+] {len(productos)} productos registrados con su SHA-256")
    else:
        print("  [=] Ya existen productos, no se insertan los de prueba")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    from scripts.generar_productos import generar_productos

    cargar_datos_prueba(Config.DB_PATH, generar_productos(Config.PRODUCTS_DIR))
