"""
Crea la PKI local del proyecto:

    1. Autoridad Certificadora local (CA raíz)         -> certificados/ca.crt     + secretos/ca.key
    2. Certificado del servidor firmado por la CA       -> certificados/servidor.crt + secretos/servidor.key
       (y certificados/servidor_cadena.crt = servidor + CA, lo que entrega el servidor HTTPS)
    3. Certificado AUTOFIRMADO "no confiable"           -> certificados/no_confiable.crt + secretos/no_confiable.key
       (sirve para demostrar que el cliente rechaza un certificado que no emitió la CA)

Uso:
    python scripts/crear_ca.py              # crea lo que falte
    python scripts/crear_ca.py --forzar     # vuelve a generar todo

Las claves privadas van a secretos/ (permisos 600, excluida del repositorio).
Equivalente con OpenSSL: scripts/crear_ca_openssl.sh
"""
import argparse
import ipaddress
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import escribir_secreto  # noqa: E402

NOMBRES_SERVIDOR = ["localhost", "plataforma.local"]
IPS_SERVIDOR = ["127.0.0.1"]


def _nombre(cn, ou):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Chihuahua"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Ciudad Juarez"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Plataforma Segura de Contenido Digital"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _guardar_clave(clave, ruta):
    pem = clave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    escribir_secreto(ruta, pem)


def _guardar_cert(cert, ruta):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _san():
    return x509.SubjectAlternativeName(
        [x509.DNSName(n) for n in NOMBRES_SERVIDOR] + [x509.IPAddress(ipaddress.ip_address(i)) for i in IPS_SERVIDOR]
    )


def crear_ca(certs: Path, secretos: Path):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    nombre = _nombre("CA Local Plataforma Segura", "Autoridad Certificadora")
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
        .sign(clave, hashes.SHA256())
    )
    _guardar_clave(clave, secretos / "ca.key")
    _guardar_cert(cert, certs / "ca.crt")
    return clave, cert


def crear_servidor(certs: Path, secretos: Path, ca_clave, ca_cert):
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_nombre("localhost", "Servidor de aplicacion"))
        .issuer_name(ca_cert.subject)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=397))  # límite aceptado por navegadores
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(_san(), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_clave.public_key()), critical=False
        )
        .sign(ca_clave, hashes.SHA256())
    )
    _guardar_clave(clave, secretos / "servidor.key")
    _guardar_cert(cert, certs / "servidor.crt")
    cadena = cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM)
    (certs / "servidor_cadena.crt").write_bytes(cadena)


def crear_no_confiable(certs: Path, secretos: Path):
    """Autofirmado con los mismos nombres que el servidor, pero sin la CA local."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = _nombre("localhost", "Certificado NO confiable (autofirmado)")
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=397))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(_san(), critical=False)
        .sign(clave, hashes.SHA256())
    )
    _guardar_clave(clave, secretos / "no_confiable.key")
    _guardar_cert(cert, certs / "no_confiable.crt")


def generar_pki(certs: Path, secretos: Path, forzar=False):
    certs.mkdir(parents=True, exist_ok=True)
    secretos.mkdir(parents=True, exist_ok=True)
    if forzar or not (certs / "ca.crt").exists() or not (secretos / "ca.key").exists():
        ca_clave, ca_cert = crear_ca(certs, secretos)
        print("  [+] CA local creada: certificados/ca.crt")
        crear_servidor(certs, secretos, ca_clave, ca_cert)
        print("  [+] Certificado del servidor emitido por la CA: certificados/servidor.crt")
    elif not (certs / "servidor.crt").exists() or not (secretos / "servidor.key").exists():
        ca_clave = serialization.load_pem_private_key((secretos / "ca.key").read_bytes(), None)
        ca_cert = x509.load_pem_x509_certificate((certs / "ca.crt").read_bytes())
        crear_servidor(certs, secretos, ca_clave, ca_cert)
        print("  [+] Certificado del servidor emitido por la CA: certificados/servidor.crt")
    else:
        print("  [=] PKI existente, se conserva")
    if forzar or not (certs / "no_confiable.crt").exists() or not (secretos / "no_confiable.key").exists():
        crear_no_confiable(certs, secretos)
        print("  [+] Certificado autofirmado NO confiable: certificados/no_confiable.crt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--forzar", action="store_true", help="regenerar todos los certificados")
    args = parser.parse_args()
    generar_pki(Config.CERTS_DIR, Config.SECRETS_DIR, args.forzar)
