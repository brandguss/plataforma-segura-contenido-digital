"""
Módulo criptográfico de la plataforma.

Se usan exclusivamente bibliotecas probadas (cryptography, hashlib, argon2-cffi);
no se implementa ningún algoritmo desde cero.

Contenido:
  * SHA-256 de archivos (integridad de productos y copias).
  * Firma digital RSA-PSS/SHA-256 de comprobantes (integridad + no repudio).
  * Cifrado autenticado AES-256-GCM (confidencialidad de los respaldos).
  * Carga y generación de claves con permisos restringidos.
"""
import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIRMA_ALGORITMO = "RSA-PSS-SHA256"


# ---------------------------------------------------------------------------
# Hash SHA-256
# ---------------------------------------------------------------------------
def sha256_bytes(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def sha256_archivo(ruta) -> str:
    """Hash de un archivo leído por bloques (no carga todo en memoria)."""
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def sha256_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Manejo de archivos secretos
# ---------------------------------------------------------------------------
def escribir_secreto(ruta: Path, datos: bytes):
    """Escribe un archivo secreto y restringe sus permisos a 600 (solo dueño).

    En Windows chmod solo controla el atributo de solo lectura; ahí la
    protección real la da la ACL de la carpeta del usuario.
    """
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "wb") as f:
        f.write(datos)
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass


def leer_secreto(ruta: Path) -> bytes:
    if not ruta.exists():
        raise FileNotFoundError(
            f"No existe el archivo secreto {ruta}. Ejecuta: python scripts/instalar.py"
        )
    return ruta.read_bytes()


def generar_clave_simetrica(ruta: Path, longitud=32):
    """Clave aleatoria (32 bytes = 256 bits) generada con un CSPRNG."""
    escribir_secreto(ruta, secrets.token_bytes(longitud))


# ---------------------------------------------------------------------------
# Firma digital de comprobantes (RSA-PSS + SHA-256)
# ---------------------------------------------------------------------------
def generar_par_firma(ruta_privada: Path, ruta_publica: Path, bits=3072):
    """Genera el par de claves RSA para firmar comprobantes.

    La privada se guarda en secretos/ (permisos 600, fuera del repositorio).
    La pública se guarda en claves_publicas/ para que cualquiera verifique.
    """
    privada = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem_privada = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_publica = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    escribir_secreto(ruta_privada, pem_privada)
    ruta_publica.parent.mkdir(parents=True, exist_ok=True)
    ruta_publica.write_bytes(pem_publica)


def cargar_privada(ruta: Path):
    return serialization.load_pem_private_key(leer_secreto(ruta), password=None)


def cargar_publica(ruta: Path):
    return serialization.load_pem_public_key(Path(ruta).read_bytes())


def huella_publica(publica) -> str:
    """Identificador de la clave: SHA-256 de la clave pública en formato DER."""
    der = publica.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)[:32]


def json_canonico(datos: dict) -> str:
    """Serialización determinista: mismas claves ordenadas y sin espacios.

    Es indispensable para que el firmante y el verificador hasheen exactamente
    los mismos bytes.
    """
    return json.dumps(datos, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def firmar(privada, mensaje: bytes) -> str:
    """Hash SHA-256 del mensaje + firma RSA-PSS. Devuelve la firma en Base64."""
    firma = privada.sign(
        mensaje,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(firma).decode("ascii")


def verificar(publica, mensaje: bytes, firma_b64: str) -> bool:
    """True solo si la firma corresponde al mensaje exacto y a la clave pública."""
    try:
        firma = base64.b64decode(firma_b64, validate=True)
        publica.verify(
            firma,
            mensaje,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verificar_comprobante(publica, comprobante: dict) -> bool:
    """Verifica un comprobante exportado {contenido, firma, algoritmo, key_id}."""
    if not isinstance(comprobante, dict):
        return False
    contenido = comprobante.get("contenido")
    firma = comprobante.get("firma")
    if not isinstance(contenido, dict) or not isinstance(firma, str):
        return False
    return verificar(publica, json_canonico(contenido).encode("utf-8"), firma)


# ---------------------------------------------------------------------------
# Cifrado autenticado AES-256-GCM (respaldos)
# ---------------------------------------------------------------------------
CABECERA_RESPALDO = b"PSCBK1"  # identifica el formato del archivo cifrado


def cifrar(clave: bytes, datos: bytes, aad: bytes = CABECERA_RESPALDO) -> bytes:
    """Formato de salida: CABECERA | nonce(12) | ciphertext+tag(16)."""
    nonce = secrets.token_bytes(12)
    return CABECERA_RESPALDO + nonce + AESGCM(clave).encrypt(nonce, datos, aad)


def descifrar(clave: bytes, blob: bytes, aad: bytes = CABECERA_RESPALDO) -> bytes:
    """Lanza ValueError si el archivo fue alterado o la clave es incorrecta."""
    if not blob.startswith(CABECERA_RESPALDO):
        raise ValueError("Formato de respaldo desconocido")
    cuerpo = blob[len(CABECERA_RESPALDO):]
    nonce, cifrado = cuerpo[:12], cuerpo[12:]
    try:
        return AESGCM(clave).decrypt(nonce, cifrado, aad)
    except InvalidTag as exc:
        raise ValueError("El respaldo fue modificado o la clave no corresponde") from exc
