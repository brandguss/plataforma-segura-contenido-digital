"""
Prueba de TLS desde el lado del cliente (con el servidor ya en ejecución).

    Terminal 1:  python -m aplicacion                 (certificado de la CA local, puerto 8443)
    Terminal 2:  python -m aplicacion --no-confiable  (certificado autofirmado, puerto 8444)
    Terminal 3:  python scripts/probar_tls.py

El cliente confía ÚNICAMENTE en certificados/ca.crt:
    * 8443 -> conexión aceptada (cadena válida hasta la CA local, nombre localhost correcto)
    * 8444 -> conexión rechazada (CERTIFICATE_VERIFY_FAILED: emisor desconocido)
"""
import socket
import ssl
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402


def probar(host: str, puerto: int, ca: Path) -> dict:
    ctx = ssl.create_default_context(cafile=str(ca))   # solo confía en la CA local
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                cert = tls.getpeercert()
                emisor = dict(x[0] for x in cert["issuer"])
                return {
                    "puerto": puerto,
                    "aceptada": True,
                    "version_tls": tls.version(),
                    "cifrado": tls.cipher()[0],
                    "emisor": emisor.get("commonName"),
                    "sujeto": dict(x[0] for x in cert["subject"]).get("commonName"),
                    "vigencia": cert["notAfter"],
                }
    except ssl.SSLCertVerificationError as e:
        return {"puerto": puerto, "aceptada": False, "error": f"{e.reason}: {e.verify_message}"}
    except OSError as e:
        return {"puerto": puerto, "aceptada": False, "error": f"No se pudo conectar ({e}). ¿El servidor está en ejecución?"}


if __name__ == "__main__":
    ca = Config.CERTS_DIR / "ca.crt"
    for puerto, esperado in ((Config.PORT, True), (Config.UNTRUSTED_PORT, False)):
        r = probar("127.0.0.1", puerto, ca)
        estado = "ACEPTADA" if r["aceptada"] else "RECHAZADA"
        print(f"Puerto {puerto}: conexión {estado}  (esperado: {'aceptada' if esperado else 'rechazada'})")
        for k, v in r.items():
            if k not in ("puerto", "aceptada"):
                print(f"    {k}: {v}")
