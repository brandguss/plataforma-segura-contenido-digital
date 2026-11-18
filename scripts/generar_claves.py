"""
Genera las claves de la aplicación (solo las que falten):

    secretos/firma_privada.pem        RSA-3072 para firmar comprobantes   (PRIVADA)
    claves_publicas/firma_publica.pem clave pública para verificar firmas (PÚBLICA)
    secretos/fingerprint.key          256 bits para el HMAC del fingerprint
    secretos/respaldo.key             256 bits para cifrar respaldos (AES-256-GCM)
    secretos/app_secret.key           256 bits para firmar cookies CSRF de visitantes

Uso:  python scripts/generar_claves.py [--forzar]

ADVERTENCIA: regenerar la clave de firma invalida la verificación de los
comprobantes anteriores; regenerar respaldo.key impide abrir respaldos previos.
"""
import argparse
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import generar_clave_simetrica, generar_par_firma  # noqa: E402


def generar_claves(secretos: Path, publicas: Path, forzar=False):
    secretos.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secretos, 0o700)  # carpeta accesible solo para el dueño (Linux/macOS)
    except OSError:
        pass
    privada = secretos / Config.SIGNING_PRIVATE_KEY
    publica = publicas / Config.SIGNING_PUBLIC_KEY
    if forzar or not privada.exists() or not publica.exists():
        generar_par_firma(privada, publica)
        print("  [+] Par de claves de firma RSA-3072 (claves_publicas/firma_publica.pem)")
    else:
        print("  [=] Clave de firma existente, se conserva")

    for nombre, descripcion in (
        (Config.FINGERPRINT_KEY, "Clave HMAC de fingerprint"),
        (Config.BACKUP_KEY, "Clave AES-256 de respaldos"),
        (Config.APP_SECRET, "Clave secreta de la aplicación"),
    ):
        ruta = secretos / nombre
        if forzar or not ruta.exists():
            generar_clave_simetrica(ruta)
            print(f"  [+] {descripcion}: secretos/{nombre}")
        else:
            print(f"  [=] {descripcion} existente, se conserva")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--forzar", action="store_true")
    args = parser.parse_args()
    generar_claves(Config.SECRETS_DIR, Config.PUBLIC_KEYS_DIR, args.forzar)
