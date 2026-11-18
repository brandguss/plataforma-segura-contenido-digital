"""
Verificación independiente de un comprobante firmado (no necesita la app ni la BD).

    python scripts/verificar_comprobante.py comprobante_orden_1.json
    python scripts/verificar_comprobante.py comprobante.json --clave claves_publicas/firma_publica.pem

Cualquier persona con la clave pública puede comprobar que el comprobante no
fue modificado y que lo emitió quien posee la clave privada (no repudio).
"""
import argparse
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from aplicacion.config import Config  # noqa: E402
from aplicacion.criptografia import cargar_publica, huella_publica, verificar_comprobante  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("comprobante", type=Path)
    parser.add_argument("--clave", type=Path, default=Config.PUBLIC_KEYS_DIR / Config.SIGNING_PUBLIC_KEY)
    args = parser.parse_args()

    publica = cargar_publica(args.clave)
    datos = json.loads(args.comprobante.read_text(encoding="utf-8"))
    valido = verificar_comprobante(publica, datos)
    print(f"Clave pública: {args.clave}  (key_id {huella_publica(publica)})")
    print(f"Comprobante:   {args.comprobante}")
    print("Resultado:     FIRMA VÁLIDA" if valido else "Resultado:     FIRMA INVÁLIDA (alterado o emisor distinto)")
    sys.exit(0 if valido else 1)
