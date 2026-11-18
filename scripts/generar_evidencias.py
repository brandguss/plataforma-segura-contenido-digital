"""
Genera todas las evidencias de pruebas en evidencias/.

    python scripts/generar_evidencias.py

1. Ejecuta la suite completa de pytest y guarda la salida (salida_pytest.txt).
   La suite produce resultados_pruebas.md/.json, comprobante_original.json,
   comprobante_modificado.json y copia_con_fingerprint.pdf.
2. Verifica los comprobantes de evidencia con la clave pública del proyecto.
3. Detecta el fingerprint en la copia de evidencia.
4. Compara visualmente el original y la copia (imperceptibilidad) y guarda
   las imágenes renderizadas.
5. Verifica la integridad SHA-256 de los productos.
"""
import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

EVID = RAIZ / "evidencias"


def ejecutar(titulo, comando, archivo):
    print(f"\n== {titulo} ==")
    entorno = {**os.environ, "PYTHONIOENCODING": "utf-8"}  # salida UTF-8 también en Windows
    r = subprocess.run(comando, cwd=RAIZ, capture_output=True, text=True, encoding="utf-8", errors="replace", env=entorno)
    salida = f"$ {' '.join(str(c) for c in comando)}\n\n{r.stdout}{r.stderr}"
    (EVID / archivo).write_text(salida, encoding="utf-8")
    print(r.stdout[-1500:] if r.stdout else r.stderr[-1500:])
    return r.returncode


def comparar_render():
    import pypdfium2 as pdfium
    from PIL import ImageChops

    original = RAIZ / "productos" / "guia_sql_consultas.pdf"
    copia = EVID / "copia_con_fingerprint.pdf"
    a = pdfium.PdfDocument(original.read_bytes())
    b = pdfium.PdfDocument(copia.read_bytes())
    lineas = [f"Original: {original.name} ({len(a)} páginas)", f"Copia:    {copia.name} ({len(b)} páginas)", ""]
    for i in range(len(a)):
        img_a = a[i].render(scale=2).to_pil().convert("RGB")
        img_b = b[i].render(scale=2).to_pil().convert("RGB")
        caja = ImageChops.difference(img_a, img_b).getbbox()
        lineas.append(f"Página {i + 1}: {'IDÉNTICA píxel a píxel' if caja is None else f'diferencia en {caja}'}")
        if i == 1:
            img_a.save(EVID / "render_original_pag2.png")
            img_b.save(EVID / "render_copia_fingerprint_pag2.png")
    texto = "\n".join(lineas)
    (EVID / "imperceptibilidad_fingerprint.txt").write_text(texto + "\n", encoding="utf-8")
    print("\n== Imperceptibilidad del fingerprint ==\n" + texto)


if __name__ == "__main__":
    EVID.mkdir(exist_ok=True)
    py = sys.executable
    codigo = ejecutar("Suite de pruebas", [py, "-m", "pytest", "tests", "-v", "-p", "no:cacheprovider"], "salida_pytest.txt")
    ejecutar("Comprobante original", [py, "scripts/verificar_comprobante.py", "evidencias/comprobante_original.json"],
             "verificacion_comprobante_original.txt")
    ejecutar("Comprobante modificado", [py, "scripts/verificar_comprobante.py", "evidencias/comprobante_modificado.json"],
             "verificacion_comprobante_modificado.txt")
    ejecutar("Detección de fingerprint", [py, "scripts/detectar_fingerprint.py", "evidencias/copia_con_fingerprint.pdf"],
             "deteccion_fingerprint.txt")
    ejecutar("Integridad de productos", [py, "scripts/verificar_hash.py"], "integridad_productos.txt")
    comparar_render()
    print(f"\nEvidencias guardadas en {EVID}")
    sys.exit(codigo)
