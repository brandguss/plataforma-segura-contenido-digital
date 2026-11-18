"""
Arranque del servidor HTTPS.

    python -m aplicacion                 -> https://127.0.0.1:8443  (certificado emitido por la CA local)
    python -m aplicacion --no-confiable  -> https://127.0.0.1:8444  (certificado autofirmado, para la prueba de rechazo)

Solo se acepta TLS 1.2 o superior. El servidor de desarrollo de Werkzeug es
suficiente para el proyecto; en producción se colocaría detrás de Nginx
o se usaría Gunicorn con la misma configuración TLS.
"""
import argparse
import ssl
import sys

from .config import Config


def contexto_tls(certificado, clave):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")   # solo suites con secreto perfecto hacia adelante
    ctx.load_cert_chain(certfile=str(certificado), keyfile=str(clave))
    return ctx


def main():
    parser = argparse.ArgumentParser(description="Servidor HTTPS de la plataforma")
    parser.add_argument("--no-confiable", action="store_true", help="Usar el certificado autofirmado no confiable")
    args = parser.parse_args()

    certs, secretos = Config.CERTS_DIR, Config.SECRETS_DIR
    if args.no_confiable:
        cert, clave, puerto = certs / "no_confiable.crt", secretos / "no_confiable.key", Config.UNTRUSTED_PORT
    else:
        cert, clave, puerto = certs / "servidor_cadena.crt", secretos / Config.SERVER_KEY, Config.PORT

    if not cert.exists() or not clave.exists():
        sys.exit("Faltan certificados. Ejecuta primero: python scripts/instalar.py")

    from . import create_app

    app = create_app()
    print(f"Servidor HTTPS en https://localhost:{puerto}  (certificado: {cert.name})")
    app.run(host=Config.HOST, port=puerto, ssl_context=contexto_tls(cert, clave), debug=False)


if __name__ == "__main__":
    main()
