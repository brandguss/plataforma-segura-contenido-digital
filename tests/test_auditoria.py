"""
Pruebas de auditoría (sección 23).

A diferencia de las demás pruebas, estas DEMUESTRAN las condiciones de los
hallazgos documentados en docs/auditoria.md: pasan mientras la debilidad
exista. Cuando se aplique la recomendación de un hallazgo, su prueba fallará
y deberá reescribirse para verificar el control nuevo.
"""
import io

import pypdfium2 as pdfium

from aplicacion import fingerprint
from aplicacion.config import Config
from aplicacion.criptografia import leer_secreto
from aplicacion.db import conectar
from conftest import comprar, iniciar_sesion, nuevo_cliente


# H1 -------------------------------------------------------------------------
def test_h1_bloqueo_por_cuenta_permite_negar_el_servicio(app):
    atacante = nuevo_cliente(app)
    for _ in range(5):
        iniciar_sesion(atacante, "CLIENTE", password="adivinanza123")
    victima = nuevo_cliente(app)
    # La víctima conoce su contraseña correcta, pero queda fuera durante 15 minutos
    assert iniciar_sesion(victima, "CLIENTE").status_code == 401


def test_h1_sin_limite_por_ip_permite_rociado_de_contrasenas(app):
    atacante = nuevo_cliente(app)  # siempre la misma IP de origen
    for rol in ("CLIENTE", "CLIENTE2", "OPERADOR"):
        for _ in range(4):  # un intento menos que el umbral de bloqueo
            iniciar_sesion(atacante, rol, password="Primavera2026")
    conn = conectar(app.config["DB_PATH"])
    fallidos = conn.execute("SELECT COUNT(*) FROM security_events WHERE event = 'LOGIN_FAILED'").fetchone()[0]
    bloqueadas = conn.execute("SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL").fetchone()[0]
    conn.close()
    assert fallidos == 12 and bloqueadas == 0
    # La IP sigue pudiendo intentar: no existe un límite por origen
    assert iniciar_sesion(atacante, "CLIENTE").status_code == 302


# H2 -------------------------------------------------------------------------
def test_h2_administrador_entra_con_un_solo_factor(client):
    r = iniciar_sesion(client, "ADMINISTRADOR")
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin/usuarios")
    assert client.get("/admin/usuarios").status_code == 200


# H3 -------------------------------------------------------------------------
def test_h3_fingerprint_no_sobrevive_rasterizado(client):
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 1)
    copia = client.get(f"/cliente/descargar/{orden}/1").data
    clave = leer_secreto(Config.SECRETS_DIR / Config.FINGERPRINT_KEY)
    assert fingerprint.extraer(copia, clave)["encontrado"]

    # "Imprimir a imagen": cada página se convierte en una imagen y se arma un PDF nuevo
    doc = pdfium.PdfDocument(copia)
    paginas = [doc[i].render(scale=1).to_pil().convert("RGB") for i in range(len(doc))]
    salida = io.BytesIO()
    paginas[0].save(salida, format="PDF", save_all=True, append_images=paginas[1:])
    assert not fingerprint.extraer(salida.getvalue(), clave)["encontrado"]


# H4 -------------------------------------------------------------------------
def test_h4_base_de_datos_legible_sin_clave(app):
    contenido = app.config["DB_PATH"].read_bytes()
    assert b"SQLite format 3" in contenido[:16]
    assert b"cliente1@demo.local" in contenido and b"$argon2id$" in contenido


# H5 -------------------------------------------------------------------------
def test_h5_claves_privadas_sin_frase_de_paso_junto_a_la_aplicacion():
    for nombre in ("firma_privada.pem", "ca.key", "servidor.key"):
        pem = (Config.SECRETS_DIR / nombre).read_bytes()
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")      # PKCS#8 sin cifrar
        assert b"ENCRYPTED" not in pem
    # La clave de la CA vive en el mismo servidor que la aplicación
    assert (Config.SECRETS_DIR / "ca.key").exists() and (Config.SECRETS_DIR / "servidor.key").exists()
