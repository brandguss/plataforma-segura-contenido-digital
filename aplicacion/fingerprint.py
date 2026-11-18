"""
Módulo de fingerprinting (esteganografía aplicada a PDF).

Cada descarga produce una copia del PDF con un identificador único insertado en
el CONTENIDO del documento (no en el nombre del archivo).

Identificador (payload):
    SCD1-<fid>-U<usuario>-O<orden>-P<producto>-<etiqueta>

    fid       8 hex aleatorios (distingue descargas repetidas del mismo producto)
    etiqueta  primeros 16 hex de HMAC-SHA256(clave_fingerprint, fid|usuario|orden|producto)
              -> impide fabricar o alterar un fingerprint sin conocer la clave.

Técnica de inserción (dos capas redundantes):
    1. Capa de texto invisible en CADA página: el payload se escribe con el
       modo de renderizado de texto 3 de PDF ("ni relleno ni contorno"), que
       el visor no dibuja pero que forma parte del flujo de contenido de la
       página. Se inserta dos veces por página (margen inferior y superior).
    2. Metadato del documento: clave personalizada /Fingerprint en el
       diccionario Info del PDF.

Justificación:
    * Imperceptibilidad: el render de la copia es idéntico píxel a píxel al
      original (se demuestra en evidencias/ con pypdfium2).
    * Robustez: sobrevive a renombrar el archivo, a eliminar los metadatos y a
      extraer páginas sueltas (cada página lleva su propia copia). No sobrevive
      a imprimir/escanear o rasterizar el PDF (limitación documentada).
    * Capacidad: ~50 caracteres por inserción, 2 inserciones por página más el
      metadato; suficiente para identificar usuario, orden, producto y descarga.
"""
import hashlib
import hmac
import io
import re
import secrets

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

PREFIJO = "SCD1"
PATRON = re.compile(r"SCD1-([0-9a-f]{8})-U(\d+)-O(\d+)-P(\d+)-([0-9a-f]{16})")
CLAVE_METADATO = "/Fingerprint"


def _etiqueta(clave: bytes, fid: str, usuario: int, orden: int, producto: int) -> str:
    mensaje = f"{fid}|{usuario}|{orden}|{producto}".encode("ascii")
    return hmac.new(clave, mensaje, hashlib.sha256).hexdigest()[:16]


def generar_payload(clave: bytes, usuario: int, orden: int, producto: int) -> str:
    """Genera el identificador único de una descarga."""
    fid = secrets.token_hex(4)
    etiqueta = _etiqueta(clave, fid, usuario, orden, producto)
    return f"{PREFIJO}-{fid}-U{usuario}-O{orden}-P{producto}-{etiqueta}"


def _capa_invisible(ancho: float, alto: float, payload: str) -> PdfReader:
    """Crea una página PDF transparente que contiene el payload en texto invisible."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=(ancho, alto))
    for y in (4, alto - 8):                     # margen inferior y superior
        texto = c.beginText(6, y)
        texto.setTextRenderMode(3)              # modo 3 = invisible
        texto.setFont("Helvetica", 4)
        texto.textLine(payload)
        c.drawText(texto)
    c.showPage()
    c.save()
    buffer.seek(0)
    return PdfReader(buffer)


def insertar(pdf_original: bytes, payload: str) -> bytes:
    """Devuelve una copia del PDF con el fingerprint insertado en el contenido."""
    lector = PdfReader(io.BytesIO(pdf_original))
    escritor = PdfWriter(clone_from=lector)
    for pagina in escritor.pages:
        caja = pagina.mediabox
        capa = _capa_invisible(float(caja.width), float(caja.height), payload)
        pagina.merge_page(capa.pages[0])

    metadatos = {k: v for k, v in (lector.metadata or {}).items() if isinstance(v, str)}
    metadatos[CLAVE_METADATO] = payload
    escritor.add_metadata(metadatos)

    salida = io.BytesIO()
    escritor.write(salida)
    return salida.getvalue()


def _decodificar(coincidencia, clave: bytes):
    fid, usuario, orden, producto, etiqueta = coincidencia.groups()
    usuario, orden, producto = int(usuario), int(orden), int(producto)
    esperada = _etiqueta(clave, fid, usuario, orden, producto)
    return {
        "fingerprint": coincidencia.group(0),
        "fid": fid,
        "user_id": usuario,
        "order_id": orden,
        "product_id": producto,
        "autentico": hmac.compare_digest(esperada, etiqueta),
    }


def extraer(pdf: bytes, clave: bytes) -> dict:
    """Busca el fingerprint en el texto de las páginas y en los metadatos.

    Devuelve un diccionario con el resultado de cada capa y el identificador
    recuperado (o None si no se encontró).
    """
    lector = PdfReader(io.BytesIO(pdf))
    encontrados = {}
    fuentes = {"metadato": False, "texto_paginas": 0, "paginas": len(lector.pages)}

    # Capa 1: texto invisible en cada página
    for pagina in lector.pages:
        texto = re.sub(r"\s+", "", pagina.extract_text() or "")
        hallados = PATRON.findall(texto)
        if hallados:
            fuentes["texto_paginas"] += 1
        for m in PATRON.finditer(texto):
            encontrados[m.group(0)] = _decodificar(m, clave)

    # Capa 2: metadato del documento
    meta = (lector.metadata or {}).get(CLAVE_METADATO)
    if isinstance(meta, str):
        m = PATRON.search(meta)
        if m:
            fuentes["metadato"] = True
            encontrados[m.group(0)] = _decodificar(m, clave)

    autenticos = [r for r in encontrados.values() if r["autentico"]]
    return {
        "encontrado": bool(autenticos),
        "resultado": autenticos[0] if autenticos else None,
        "candidatos": list(encontrados.values()),
        "fuentes": fuentes,
    }
