"""
Las 13 pruebas mínimas obligatorias de la sección 19 del proyecto.

Cada prueba registra su resultado con la fixture `evidencia`, que al final
genera evidencias/resultados_pruebas.md.
"""
import json
import socket
import ssl
import threading

import pytest
from werkzeug.serving import make_server

from aplicacion import fingerprint
from aplicacion.__main__ import contexto_tls
from aplicacion.config import Config
from aplicacion.criptografia import cargar_publica, leer_secreto, sha256_archivo, verificar_comprobante
from aplicacion.db import conectar
from conftest import nuevo_cliente, comprar, iniciar_sesion, token_actual


def _eventos(app, evento):
    conn = conectar(app.config["DB_PATH"])
    filas = conn.execute("SELECT * FROM security_events WHERE event = ? ORDER BY id", (evento,)).fetchall()
    conn.close()
    return filas


# 1 -------------------------------------------------------------------------
def test_01_contrasena_incorrecta(client, app, evidencia):
    r = iniciar_sesion(client, "CLIENTE", password="ContraseñaIncorrecta123")
    acceso = client.get("/cliente/ordenes")
    eventos = _eventos(app, "LOGIN_FAILED")
    ok = r.status_code == 401 and acceso.status_code == 302 and len(eventos) == 1
    evidencia(
        1, "Contraseña incorrecta", "Acceso rechazado",
        f"HTTP {r.status_code}; /cliente/ordenes redirige a login", ok,
        f"Evento LOGIN_FAILED registrado: {eventos[0]['details'] if eventos else '—'}",
    )
    assert ok


# 2 -------------------------------------------------------------------------
def test_02_cliente_funcion_administrativa(client, app, evidencia):
    iniciar_sesion(client, "CLIENTE")
    r_get = client.get("/admin/usuarios")
    r_post = client.post("/admin/usuario/3/rol", data={"csrf_token": token_actual(client), "role": "ADMINISTRADOR"})
    r_oper = client.get("/operador/productos")
    conn = conectar(app.config["DB_PATH"])
    rol = conn.execute("SELECT role FROM users WHERE id = 3").fetchone()["role"]
    conn.close()
    ok = r_get.status_code == 403 and r_post.status_code == 403 and r_oper.status_code == 403 and rol == "CLIENTE"
    evidencia(
        2, "CLIENTE intenta una función administrativa", "Acceso rechazado",
        f"GET /admin/usuarios → {r_get.status_code}; POST cambio de rol → {r_post.status_code}", ok,
        f"También /operador/productos → {r_oper.status_code}. Rol sin cambios: {rol}. "
        f"Eventos ACCESS_DENIED: {len(_eventos(app, 'ACCESS_DENIED'))}",
    )
    assert ok


# 3 -------------------------------------------------------------------------
def test_03_operador_cambiar_roles(client, app, evidencia):
    iniciar_sesion(client, "OPERADOR")
    r = client.post("/admin/usuario/3/rol", data={"csrf_token": token_actual(client), "role": "OPERADOR"})
    conn = conectar(app.config["DB_PATH"])
    rol = conn.execute("SELECT role FROM users WHERE id = 3").fetchone()["role"]
    conn.close()
    ok = r.status_code == 403 and rol == "CLIENTE"
    evidencia(
        3, "OPERADOR intenta cambiar roles", "Acceso rechazado", f"HTTP {r.status_code}", ok,
        f"El rol del usuario 3 sigue siendo {rol}; evento ACCESS_DENIED registrado",
    )
    assert ok


# 4 -------------------------------------------------------------------------
def test_04_administrador_autorizado(client, app, evidencia):
    iniciar_sesion(client, "ADMINISTRADOR")
    r = client.post("/admin/usuario/3/rol", data={"csrf_token": token_actual(client), "role": "OPERADOR"})
    conn = conectar(app.config["DB_PATH"])
    rol = conn.execute("SELECT role FROM users WHERE id = 3").fetchone()["role"]
    conn.close()
    eventos = _eventos(app, "ROLE_CHANGED")
    ok = r.status_code == 302 and rol == "OPERADOR" and eventos and eventos[-1]["result"] == "EXITO"
    evidencia(
        4, "ADMINISTRADOR autorizado", "Operación permitida", f"HTTP {r.status_code}; rol nuevo = {rol}", ok,
        f"Evento ROLE_CHANGED: {eventos[-1]['details'] if eventos else '—'}",
    )
    assert ok


# 5 y 6: TLS ----------------------------------------------------------------
@pytest.fixture
def servidores_tls(app):
    """Levanta dos servidores HTTPS reales: uno con el certificado de la CA y otro autofirmado."""
    certs, secretos = Config.CERTS_DIR, Config.SECRETS_DIR
    servidores = {
        "confiable": make_server("127.0.0.1", 0, app, threaded=True,
                                 ssl_context=contexto_tls(certs / "servidor_cadena.crt", secretos / "servidor.key")),
        "no_confiable": make_server("127.0.0.1", 0, app, threaded=True,
                                    ssl_context=contexto_tls(certs / "no_confiable.crt", secretos / "no_confiable.key")),
    }
    hilos = [threading.Thread(target=s.serve_forever, daemon=True) for s in servidores.values()]
    for h in hilos:
        h.start()
    yield {k: s.server_port for k, s in servidores.items()}
    for s in servidores.values():
        s.shutdown()


def _conectar_tls(puerto):
    ctx = ssl.create_default_context(cafile=str(Config.CERTS_DIR / "ca.crt"))  # solo la CA local
    with socket.create_connection(("127.0.0.1", puerto), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            primera_linea = tls.recv(64).split(b"\r\n")[0].decode()
            emisor = dict(x[0] for x in tls.getpeercert()["issuer"])["commonName"]
            return tls.version(), tls.cipher()[0], emisor, primera_linea


def test_05_certificado_tls_correcto(servidores_tls, evidencia):
    version, cifrado, emisor, respuesta = _conectar_tls(servidores_tls["confiable"])
    ok = respuesta.startswith("HTTP/1.1 200") and emisor == "CA Local Plataforma Segura"
    evidencia(
        5, "Certificado TLS correcto", "Conexión aceptada", f"{version} · {cifrado} · {respuesta}", ok,
        f"Cadena validada contra certificados/ca.crt; emisor: {emisor}; hostname: localhost",
    )
    assert ok


def test_06_certificado_no_confiable(servidores_tls, evidencia):
    with pytest.raises(ssl.SSLCertVerificationError) as error:
        _conectar_tls(servidores_tls["no_confiable"])
    motivo = f"{error.value.reason}: {error.value.verify_message}"
    evidencia(6, "Certificado no confiable", "Conexión rechazada", "Handshake TLS abortado por el cliente", True, motivo)


# 7 y 8: firma digital ------------------------------------------------------
def _comprobante(client, carpeta=None):
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 1)
    return orden, json.loads(client.get(f"/cliente/orden/{orden}/comprobante.json").get_data(as_text=True))


def test_07_comprobante_original(client, app, evidencia, carpeta_evidencias):
    orden, comp = _comprobante(client)
    publica = cargar_publica(Config.PUBLIC_KEYS_DIR / Config.SIGNING_PUBLIC_KEY)
    valido = verificar_comprobante(publica, comp)
    # Verificación también desde la interfaz web
    r = client.post("/cliente/verificar", data={"csrf_token": token_actual(client, "/cliente/verificar"),
                                                 "comprobante": json.dumps(comp)})
    web = "Firma VÁLIDA" in r.get_data(as_text=True)
    (carpeta_evidencias / "comprobante_original.json").write_text(json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")
    ok = valido and web and _eventos(app, "SIGNATURE_CREATED")
    evidencia(
        7, "Comprobante original", "Firma digital válida", "FIRMA VÁLIDA (biblioteca y página /cliente/verificar)", ok,
        f"Orden {orden}, {comp['algoritmo']}, key_id {comp['key_id']}. Archivo: evidencias/comprobante_original.json",
    )
    assert ok


def test_08_comprobante_modificado(client, evidencia, carpeta_evidencias):
    orden, comp = _comprobante(client)
    original = comp["contenido"]["total_centavos"]
    comp["contenido"]["total_centavos"] = 100  # un atacante intenta cambiar el total a $1.00
    publica = cargar_publica(Config.PUBLIC_KEYS_DIR / Config.SIGNING_PUBLIC_KEY)
    valido = verificar_comprobante(publica, comp)
    r = client.post("/cliente/verificar", data={"csrf_token": token_actual(client, "/cliente/verificar"),
                                                 "comprobante": json.dumps(comp)})
    web = "Firma INVÁLIDA" in r.get_data(as_text=True)
    (carpeta_evidencias / "comprobante_modificado.json").write_text(json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")
    ok = not valido and web
    evidencia(
        8, "Comprobante modificado", "Firma digital inválida", "FIRMA INVÁLIDA (biblioteca y página web)", ok,
        f"Se cambió total_centavos de {original} a 100. Archivo: evidencias/comprobante_modificado.json",
    )
    assert ok


# 9 -------------------------------------------------------------------------
def test_09_fingerprint_recuperable(client, app, evidencia, carpeta_evidencias):
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 2)
    r = client.get(f"/cliente/descargar/{orden}/2")
    copia = r.data
    (carpeta_evidencias / "copia_con_fingerprint.pdf").write_bytes(copia)
    resultado = fingerprint.extraer(copia, leer_secreto(Config.SECRETS_DIR / Config.FINGERPRINT_KEY))
    fp = resultado["resultado"]
    conn = conectar(app.config["DB_PATH"])
    usuario_id = conn.execute("SELECT id FROM users WHERE email = 'cliente1@demo.local'").fetchone()["id"]
    registro = conn.execute("SELECT * FROM downloads WHERE fingerprint = ?", (fp["fingerprint"],)).fetchone()
    conn.close()
    ok = (
        r.status_code == 200 and resultado["encontrado"] and fp["user_id"] == usuario_id
        and fp["order_id"] == orden and registro is not None and _eventos(app, "FINGERPRINT_CREATED")
    )
    evidencia(
        9, "Producto descargado", "Fingerprint recuperable", f"Recuperado {fp['fingerprint']}", ok,
        f"usuario={fp['user_id']} orden={fp['order_id']} producto={fp['product_id']}; HMAC válido; "
        f"capas: metadato={resultado['fuentes']['metadato']}, texto en {resultado['fuentes']['texto_paginas']}/"
        f"{resultado['fuentes']['paginas']} páginas. Archivo: evidencias/copia_con_fingerprint.pdf",
    )
    assert ok


# 10 ------------------------------------------------------------------------
def test_10_descargar_no_comprado(client, app, evidencia):
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 1)
    r_otro_producto = client.get(f"/cliente/descargar/{orden}/3")   # producto que no está en la orden
    # Orden de otro cliente
    client2 = nuevo_cliente(app)
    iniciar_sesion(client2, "CLIENTE2")
    r_orden_ajena = client2.get(f"/cliente/descargar/{orden}/1")
    denegados = [e for e in _eventos(app, "DOWNLOAD") if e["result"] == "DENEGADO"]
    ok = r_otro_producto.status_code == 403 and r_orden_ajena.status_code == 403 and len(denegados) == 2
    evidencia(
        10, "CLIENTE intenta descargar producto no comprado", "Acceso rechazado",
        f"Producto fuera de la orden → {r_otro_producto.status_code}; orden de otro cliente → {r_orden_ajena.status_code}",
        ok, f"{len(denegados)} eventos DOWNLOAD con resultado DENEGADO",
    )
    assert ok


# 11 y 12: hash de archivos ---------------------------------------------------
def test_11_archivo_original_hash(app, evidencia):
    conn = conectar(app.config["DB_PATH"])
    p = conn.execute("SELECT * FROM products WHERE id = 1").fetchone()
    conn.close()
    actual = sha256_archivo(app.config["PRODUCTS_DIR"] / p["file_name"])
    ok = actual == p["file_hash"]
    evidencia(11, "Archivo original", "Hash esperado", "SHA-256 coincide", ok,
              f"{p['file_name']}<br>registrado: {p['file_hash']}<br>calculado:  {actual}")
    assert ok


def test_12_archivo_modificado_hash(client, app, evidencia):
    conn = conectar(app.config["DB_PATH"])
    p = conn.execute("SELECT * FROM products WHERE id = 1").fetchone()
    conn.close()
    ruta = app.config["PRODUCTS_DIR"] / p["file_name"]
    with open(ruta, "ab") as f:
        f.write(b"\n% byte agregado por un atacante\n")   # modificación mínima
    actual = sha256_archivo(ruta)
    # La aplicación detecta la alteración y se niega a distribuir el archivo
    iniciar_sesion(client, "CLIENTE")
    orden = comprar(client, 1)
    r = client.get(f"/cliente/descargar/{orden}/1")
    fallos = _eventos(app, "INTEGRITY_FAILED")
    ok = actual != p["file_hash"] and r.status_code == 302 and len(fallos) == 1
    evidencia(
        12, "Archivo modificado", "Hash diferente", "SHA-256 distinto; descarga bloqueada", ok,
        f"registrado: {p['file_hash']}<br>calculado:  {actual}<br>Evento INTEGRITY_FAILED registrado",
    )
    assert ok


# 13 ------------------------------------------------------------------------
def test_13_restauracion_respaldo(client, app, evidencia):
    from scripts.respaldo import conteos, crear_respaldo
    from scripts.restaurar import restaurar

    iniciar_sesion(client, "CLIENTE")
    comprar(client, 1)
    comprar(client, 3)
    bd, productos = app.config["DB_PATH"], app.config["PRODUCTS_DIR"]
    carpeta = app.config["RUTA_TMP"] / "respaldos"
    antes = conteos(bd)
    archivo = crear_respaldo(bd, productos, carpeta)

    # Pérdida simulada del ambiente: se borran la BD y todos los productos
    bd.unlink()
    for pdf in productos.glob("*.pdf"):
        pdf.unlink()

    resultado = restaurar(archivo, bd, productos)
    despues = conteos(bd)
    claves = ("users", "products", "orders", "payments", "receipts")
    ok = resultado["correcto"] and all(despues[k] == antes[k] for k in claves)
    evidencia(
        13, "Restauración de respaldo", "Información crítica recuperada",
        "Usuarios, productos y órdenes recuperados", ok,
        f"Respaldo AES-256-GCM {archivo.name}. Antes: {', '.join(f'{k}={antes[k]}' for k in claves)}. "
        f"Después: {', '.join(f'{k}={despues[k]}' for k in claves)}. Productos íntegros: "
        f"{sum(resultado['productos_integros'].values())}/{len(resultado['productos_integros'])}",
    )
    assert ok
