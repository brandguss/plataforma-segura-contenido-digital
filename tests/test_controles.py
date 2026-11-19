"""
Pruebas complementarias de los controles de seguridad (más allá de las 13 obligatorias):
contraseñas, bloqueo por fuerza bruta, CSRF, sesiones, recuperación de
contraseña, bitácora inmutable, robustez del fingerprint y cabeceras HTTP.
"""
import io
import re
import sqlite3

import pypdfium2 as pdfium
import pytest
from pypdf import PdfReader, PdfWriter

from aplicacion import fingerprint
from aplicacion.config import Config
from aplicacion.criptografia import leer_secreto
from aplicacion.db import conectar
from conftest import nuevo_cliente, comprar, csrf_de, iniciar_sesion, token_actual


def _bd(app):
    return conectar(app.config["DB_PATH"])


# --- Contraseñas -------------------------------------------------------------
def test_contrasenas_solo_argon2id(app):
    conn = _bd(app)
    columnas = [c["name"] for c in conn.execute("PRAGMA table_info(users)")]
    hashes = [r["password_hash"] for r in conn.execute("SELECT password_hash FROM users")]
    conn.close()
    assert "password" not in columnas
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert "Cliente#2026Uno" not in " ".join(hashes)


def test_bloqueo_por_intentos_fallidos(client, app):
    for _ in range(5):
        iniciar_sesion(client, "CLIENTE", password="incorrecta123")
    r = iniciar_sesion(client, "CLIENTE")  # contraseña correcta, pero la cuenta está bloqueada
    assert r.status_code == 401
    conn = _bd(app)
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE event = 'ACCOUNT_LOCKED'").fetchone()[0] == 1
    conn.close()


def test_mensaje_login_no_revela_si_el_usuario_existe(client):
    r1 = iniciar_sesion(client, "CLIENTE", password="incorrecta123").get_data(as_text=True)
    token = csrf_de(client.get("/login").get_data(as_text=True))
    r2 = client.post("/login", data={"csrf_token": token, "email": "noexiste@demo.local", "password": "x"}).get_data(as_text=True)
    mensaje = "Correo o contraseña incorrectos"
    assert mensaje in r1 and mensaje in r2


# --- CSRF y sesiones ---------------------------------------------------------
def test_post_sin_csrf_rechazado(client):
    iniciar_sesion(client, "CLIENTE")
    assert client.post("/cliente/carrito/agregar/1", data={}).status_code == 400
    assert client.post("/cliente/carrito/agregar/1", data={"csrf_token": "falso"}).status_code == 400


def test_cookie_de_sesion_segura(client):
    r = iniciar_sesion(client, "CLIENTE")
    cookie = [c for c in r.headers.getlist("Set-Cookie") if c.startswith("psc_sid=")][0]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_logout_invalida_la_sesion(client):
    iniciar_sesion(client, "CLIENTE")
    client.post("/logout", data={"csrf_token": token_actual(client)})
    assert client.get("/cliente/ordenes").status_code == 302


def test_admin_revoca_sesion(app):
    cliente = nuevo_cliente(app)
    admin = nuevo_cliente(app)
    iniciar_sesion(cliente, "CLIENTE")
    assert cliente.get("/cliente/ordenes").status_code == 200
    iniciar_sesion(admin, "ADMINISTRADOR")
    html = admin.get("/admin/sesiones").get_data(as_text=True)
    sesion_id = re.search(r"cliente1@demo.local.*?/admin/sesion/(\d+)/revocar", html, re.S).group(1)
    admin.post(f"/admin/sesion/{sesion_id}/revocar", data={"csrf_token": csrf_de(html)})
    assert cliente.get("/cliente/ordenes").status_code == 302


def test_cuenta_desactivada_no_inicia_sesion(app):
    admin = nuevo_cliente(app)
    iniciar_sesion(admin, "ADMINISTRADOR")
    admin.post("/admin/usuario/3/estado", data={"csrf_token": token_actual(admin)})
    cliente = nuevo_cliente(app)
    assert iniciar_sesion(cliente, "CLIENTE").status_code == 401
    conn = _bd(app)
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE event = 'ACCOUNT_DISABLED'").fetchone()[0] == 1
    conn.close()


def test_admin_no_puede_cambiar_su_propio_rol(client, app):
    iniciar_sesion(client, "ADMINISTRADOR")
    client.post("/admin/usuario/1/rol", data={"csrf_token": token_actual(client), "role": "CLIENTE"})
    conn = _bd(app)
    assert conn.execute("SELECT role FROM users WHERE id = 1").fetchone()["role"] == "ADMINISTRADOR"
    conn.close()


def test_cliente_no_ve_ordenes_ajenas(app):
    c1 = nuevo_cliente(app)
    iniciar_sesion(c1, "CLIENTE")
    orden = comprar(c1, 1)
    c2 = nuevo_cliente(app)
    iniciar_sesion(c2, "CLIENTE2")
    assert c2.get(f"/cliente/orden/{orden}").status_code == 403
    assert c2.get(f"/cliente/orden/{orden}/comprobante.json").status_code == 403


# --- Recuperación de contraseña ----------------------------------------------
def test_token_de_recuperacion_un_solo_uso(client, app):
    token = csrf_de(client.get("/recuperar").get_data(as_text=True))
    client.post("/recuperar", data={"csrf_token": token, "email": "cliente1@demo.local"})
    correo = sorted(app.config["OUTBOX_DIR"].glob("*.txt"))[-1].read_text(encoding="utf-8")
    ruta = re.search(r"https://localhost:\d+(/restablecer/\S+)", correo).group(1)

    csrf = csrf_de(client.get(ruta).get_data(as_text=True))
    r = client.post(ruta, data={"csrf_token": csrf, "password": "NuevaClave2026x", "password2": "NuevaClave2026x"})
    assert r.status_code == 302
    assert client.get(ruta).status_code == 302  # segundo uso: rechazado
    conn = _bd(app)
    assert conn.execute("SELECT COUNT(*) FROM password_resets WHERE used_at IS NULL").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE event='PASSWORD_RESET' AND result='EXITO'").fetchone()[0] == 1
    conn.close()
    assert iniciar_sesion(client, "CLIENTE", password="NuevaClave2026x").status_code == 302


# --- Bitácora inmutable y eventos requeridos ---------------------------------
def test_bitacora_no_se_puede_borrar(client, app):
    iniciar_sesion(client, "CLIENTE")
    conn = _bd(app)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM security_events")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE security_events SET result = 'EXITO'")
    conn.close()


def test_eventos_requeridos_se_registran(app):
    cliente = nuevo_cliente(app)
    iniciar_sesion(cliente, "CLIENTE", password="incorrecta123")
    iniciar_sesion(cliente, "CLIENTE")
    orden = comprar(cliente, 1)
    cliente.get(f"/cliente/descargar/{orden}/1")
    cliente.post("/logout", data={"csrf_token": token_actual(cliente)})
    admin = nuevo_cliente(app)
    iniciar_sesion(admin, "ADMINISTRADOR")
    admin.post("/admin/usuario/4/rol", data={"csrf_token": token_actual(admin), "role": "OPERADOR"})
    admin.post("/admin/usuario/4/estado", data={"csrf_token": token_actual(admin)})
    t = csrf_de(cliente.get("/recuperar").get_data(as_text=True))
    cliente.post("/recuperar", data={"csrf_token": t, "email": "cliente1@demo.local"})
    correo = sorted(app.config["OUTBOX_DIR"].glob("*.txt"))[-1].read_text(encoding="utf-8")
    ruta = re.search(r"https://localhost:\d+(/restablecer/\S+)", correo).group(1)
    t = csrf_de(cliente.get(ruta).get_data(as_text=True))
    cliente.post(ruta, data={"csrf_token": t, "password": "OtraClave2026x", "password2": "OtraClave2026x"})

    requeridos = {
        "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "PASSWORD_RESET", "ORDER_CREATED", "PAYMENT_APPROVED",
        "DOWNLOAD", "ROLE_CHANGED", "ACCOUNT_DISABLED", "SIGNATURE_CREATED", "FINGERPRINT_CREATED",
    }
    conn = _bd(app)
    filas = conn.execute("SELECT * FROM security_events").fetchall()
    conn.close()
    presentes = {f["event"] for f in filas}
    assert requeridos <= presentes, requeridos - presentes
    # Cada registro contiene usuario, evento, fecha/hora, resultado y origen
    for f in filas:
        assert f["event"] and f["created_at"] and f["result"] and f["source"]


# --- Fingerprint: imperceptibilidad, robustez y autenticidad -----------------
@pytest.fixture
def copia(client):
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 3)
    return client.get(f"/cliente/descargar/{orden}/3").data


def _render(pdf: bytes):
    doc = pdfium.PdfDocument(pdf)
    return [doc[i].render(scale=1.5).to_pil().tobytes() for i in range(len(doc))]


def test_fingerprint_imperceptible(app, copia):
    original = (app.config["PRODUCTS_DIR"] / "apuntes_criptografia.pdf").read_bytes()
    assert _render(original) == _render(copia)   # idéntico píxel a píxel


def test_fingerprint_sobrevive_sin_metadatos(copia):
    lector = PdfReader(io.BytesIO(copia))
    escritor = PdfWriter()
    for p in lector.pages:
        escritor.add_page(p)
    escritor.add_metadata({"/Producer": "editor externo"})  # metadatos originales eliminados
    salida = io.BytesIO()
    escritor.write(salida)
    r = fingerprint.extraer(salida.getvalue(), leer_secreto(Config.SECRETS_DIR / Config.FINGERPRINT_KEY))
    assert r["encontrado"] and r["fuentes"]["metadato"] is False and r["fuentes"]["texto_paginas"] > 0


def test_fingerprint_sobrevive_extraer_una_pagina(copia):
    lector = PdfReader(io.BytesIO(copia))
    escritor = PdfWriter()
    escritor.add_page(lector.pages[2])
    salida = io.BytesIO()
    escritor.write(salida)
    r = fingerprint.extraer(salida.getvalue(), leer_secreto(Config.SECRETS_DIR / Config.FINGERPRINT_KEY))
    assert r["encontrado"]


def test_fingerprint_falsificado_es_rechazado():
    clave = leer_secreto(Config.SECRETS_DIR / Config.FINGERPRINT_KEY)
    base = (Config.PRODUCTS_DIR / "guia_sql_consultas.pdf").read_bytes()
    legitimo = fingerprint.generar_payload(clave, 3, 10, 2)
    falso = re.sub(r"-U3-", "-U4-", legitimo)  # intenta culpar a otro usuario
    r = fingerprint.extraer(fingerprint.insertar(base, falso), clave)
    assert not r["encontrado"] and r["candidatos"] and not r["candidatos"][0]["autentico"]


# --- Aplicación segura ------------------------------------------------------
def test_cabeceras_de_seguridad(client):
    r = client.get("/")
    for cabecera in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert cabecera in r.headers


def test_errores_no_revelan_detalles(client):
    r = client.get("/producto/999999")
    texto = r.get_data(as_text=True)
    assert r.status_code == 404 and "Traceback" not in texto and "sqlite" not in texto.lower()


def test_validacion_de_entradas_registro(client):
    t = csrf_de(client.get("/registro").get_data(as_text=True))
    r = client.post("/registro", data={"csrf_token": t, "name": "X", "email": "no-es-correo", "password": "corta", "password2": "corta"})
    assert r.status_code == 400


def test_registro_publico_siempre_es_cliente(client, app):
    t = csrf_de(client.get("/registro").get_data(as_text=True))
    client.post("/registro", data={"csrf_token": t, "name": "Nuevo Usuario", "email": "nuevo@demo.local",
                                   "password": "ClaveSegura2026", "password2": "ClaveSegura2026", "role": "ADMINISTRADOR"})
    conn = _bd(app)
    assert conn.execute("SELECT role FROM users WHERE email = 'nuevo@demo.local'").fetchone()["role"] == "CLIENTE"
    conn.close()


def test_precio_historico_se_conserva(app):
    cliente = nuevo_cliente(app)
    iniciar_sesion(cliente, "CLIENTE")
    orden = comprar(cliente, 1)
    operador = nuevo_cliente(app)
    iniciar_sesion(operador, "OPERADOR")
    t = token_actual(operador, "/operador/productos/1/editar")
    operador.post("/operador/productos/1/editar", data={
        "csrf_token": t, "name": "Manual de Python Básico", "price": "999.00",
        "description": "Manual introductorio de Python con ejemplos prácticos."})
    conn = _bd(app)
    assert conn.execute("SELECT price FROM products WHERE id = 1").fetchone()["price"] == 99900
    assert conn.execute("SELECT price FROM order_items WHERE order_id = ?", (orden,)).fetchone()["price"] == 14900
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE event = 'PRICE_CHANGED'").fetchone()[0] == 1
    conn.close()


def test_pago_simulado_no_guarda_numero_de_tarjeta(client, app):
    iniciar_sesion(client, "CLIENTE")
    comprar(client, 1)
    volcado = "\n".join(_bd(app).iterdump())
    assert "4242424242424242" not in volcado


def test_politica_de_contrasenas_en_el_servidor(client, app):
    """El servidor rechaza contraseñas que no cumplen los requisitos aunque se salte el verificador del navegador."""
    for password in ("clavesegura2026", "CLAVESEGURA2026", "ClaveSegura", "Corta1"):
        t = csrf_de(client.get("/registro").get_data(as_text=True))
        r = client.post("/registro", data={"csrf_token": t, "name": "Prueba", "email": "politica@demo.local",
                                           "password": password, "password2": password})
        assert r.status_code == 400, password
    conn = _bd(app)
    assert conn.execute("SELECT COUNT(*) FROM users WHERE email = 'politica@demo.local'").fetchone()[0] == 0
    conn.close()
