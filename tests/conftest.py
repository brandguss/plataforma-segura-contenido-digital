"""
Entorno de pruebas aislado.

Todo se genera en un directorio temporal (claves, PKI, productos, BD), así que
las pruebas nunca tocan los datos reales del proyecto. Cada prueba recibe una
copia limpia de la base de datos.

Al terminar, se escribe evidencias/resultados_pruebas.md con la tabla de
pruebas obligatorias (prueba, resultado esperado, resultado obtenido, detalle).
"""
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="psc_pruebas_"))

# Las rutas se leen al importar aplicacion.config: se fijan ANTES de importarla.
os.environ.update(
    {
        "PSC_DB_PATH": str(TMP / "plantilla.db"),
        "PSC_PRODUCTS_DIR": str(TMP / "productos"),
        "PSC_SECRETS_DIR": str(TMP / "secretos"),
        "PSC_CERTS_DIR": str(TMP / "certificados"),
        "PSC_PUBLIC_KEYS_DIR": str(TMP / "claves_publicas"),
        "PSC_BACKUPS_DIR": str(TMP / "respaldos"),
        "PSC_OUTBOX_DIR": str(TMP / "correo"),
        "PSC_LOG_FILE": str(TMP / "errores.log"),
    }
)
sys.path.insert(0, str(RAIZ))

from aplicacion import create_app  # noqa: E402
from aplicacion.config import Config  # noqa: E402
from base_de_datos.crear_bd import crear_bd  # noqa: E402
from base_de_datos.datos_prueba import USUARIOS_PRUEBA, cargar_datos_prueba  # noqa: E402
from scripts.crear_ca import generar_pki  # noqa: E402
from scripts.generar_claves import generar_claves  # noqa: E402
from scripts.generar_productos import generar_productos  # noqa: E402

EVIDENCIAS = Path(os.environ.get("PSC_EVIDENCE_DIR", RAIZ / "evidencias"))
_REGISTRO = []

CREDENCIALES = {rol: (email, pw) for email, pw, _, rol in USUARIOS_PRUEBA if rol != "CLIENTE"}
CREDENCIALES["CLIENTE"] = (USUARIOS_PRUEBA[2][0], USUARIOS_PRUEBA[2][1])
CREDENCIALES["CLIENTE2"] = (USUARIOS_PRUEBA[3][0], USUARIOS_PRUEBA[3][1])


# ---------------------------------------------------------------------------
# Preparación única del entorno
# ---------------------------------------------------------------------------
def pytest_sessionstart(session):
    # Si el proyecto ya está instalado, se reutilizan sus claves y certificados:
    # así las evidencias (comprobantes, copia con fingerprint) se pueden verificar
    # después con los scripts y la clave pública del repositorio. La BD y los
    # productos siempre son copias temporales.
    for carpeta in ("secretos", "certificados", "claves_publicas"):
        if (RAIZ / carpeta).is_dir() and any((RAIZ / carpeta).iterdir()):
            shutil.copytree(RAIZ / carpeta, TMP / carpeta, dirs_exist_ok=True)
    generar_claves(Config.SECRETS_DIR, Config.PUBLIC_KEYS_DIR)
    generar_pki(Config.CERTS_DIR, Config.SECRETS_DIR)
    productos = generar_productos(Config.PRODUCTS_DIR)
    crear_bd(Config.DB_PATH)
    cargar_datos_prueba(Config.DB_PATH, productos)
    shutil.copytree(Config.PRODUCTS_DIR, TMP / "productos_originales")


def pytest_sessionfinish(session, exitstatus):
    if _REGISTRO:
        EVIDENCIAS.mkdir(parents=True, exist_ok=True)
        lineas = [
            "# Resultados de las pruebas obligatorias",
            "",
            f"Generado automáticamente por `pytest` el {datetime.now():%Y-%m-%d %H:%M:%S}.",
            "",
            "| # | Prueba | Resultado esperado | Resultado obtenido | Estado | Detalle |",
            "|---|--------|--------------------|--------------------|--------|---------|",
        ]
        for i, r in enumerate(sorted(_REGISTRO, key=lambda x: x["orden"]), start=1):
            detalle = r["detalle"].replace("|", "\\|").replace("\n", "<br>")
            lineas.append(
                f"| {i} | {r['prueba']} | {r['esperado']} | {r['obtenido']} | "
                f"{'✅ PASA' if r['pasa'] else '❌ FALLA'} | {detalle} |"
            )
        (EVIDENCIAS / "resultados_pruebas.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")
        (EVIDENCIAS / "resultados_pruebas.json").write_text(
            json.dumps(sorted(_REGISTRO, key=lambda x: x["orden"]), indent=2, ensure_ascii=False), encoding="utf-8"
        )
    shutil.rmtree(TMP, ignore_errors=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def app(tmp_path):
    """Aplicación con una copia limpia de la BD y de los productos."""
    bd = tmp_path / "plataforma.db"
    shutil.copy(Config.DB_PATH, bd)
    productos = tmp_path / "productos"
    shutil.copytree(TMP / "productos_originales", productos)
    aplicacion = create_app(
        {"DB_PATH": bd, "PRODUCTS_DIR": productos, "OUTBOX_DIR": tmp_path / "correo", "TESTING": True}
    )
    aplicacion.config["RUTA_TMP"] = tmp_path
    return aplicacion


def nuevo_cliente(app):
    """Cliente de pruebas que simula peticiones HTTPS (necesario para cookies Secure)."""
    cliente = app.test_client()
    cliente.environ_base["wsgi.url_scheme"] = "https"
    return cliente


@pytest.fixture
def client(app):
    return nuevo_cliente(app)


@pytest.fixture
def evidencia():
    """Registra el resultado de una prueba obligatoria para el reporte final."""

    def registrar(orden, prueba, esperado, obtenido, pasa, detalle=""):
        _REGISTRO.append(
            {"orden": orden, "prueba": prueba, "esperado": esperado, "obtenido": obtenido, "pasa": bool(pasa), "detalle": detalle}
        )

    return registrar


@pytest.fixture
def carpeta_evidencias():
    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    return EVIDENCIAS


# ---------------------------------------------------------------------------
# Utilidades para las pruebas
# ---------------------------------------------------------------------------
def csrf_de(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "La página no contiene token CSRF"
    return m.group(1)


def iniciar_sesion(client, rol="CLIENTE", password=None):
    email, pw = CREDENCIALES[rol]
    token = csrf_de(client.get("/login").get_data(as_text=True))
    return client.post("/login", data={"csrf_token": token, "email": email, "password": password or pw})


def token_actual(client, ruta="/"):
    return csrf_de(client.get(ruta).get_data(as_text=True))


def comprar(client, producto_id=1, tarjeta="4242424242424242"):
    """Agrega un producto, crea la orden y la paga. Devuelve el id de la orden."""
    client.post(f"/cliente/carrito/agregar/{producto_id}", data={"csrf_token": token_actual(client)})
    r = client.post("/cliente/checkout", data={"csrf_token": token_actual(client, "/cliente/carrito")})
    orden_id = int(re.search(r"/orden/(\d+)/pagar", r.headers["Location"]).group(1))
    client.post(
        f"/cliente/orden/{orden_id}/pagar",
        data={"csrf_token": token_actual(client, f"/cliente/orden/{orden_id}/pagar"), "tarjeta_prueba": tarjeta},
    )
    return orden_id
