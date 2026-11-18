"""
Genera los productos digitales de prueba (PDF) en productos/.

Son documentos originales creados para el proyecto (sin material con derechos
de terceros). Se generan en modo "invariant" de ReportLab, así que el archivo
es idéntico byte a byte en cada ejecución y su SHA-256 es reproducible.

Uso:  python scripts/generar_productos.py
"""
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from reportlab.lib.pagesizes import letter  # noqa: E402
from reportlab.lib.styles import getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer  # noqa: E402

from aplicacion.config import Config  # noqa: E402

PRODUCTOS = [
    {
        "archivo": "manual_python_basico.pdf",
        "nombre": "Manual de Python Básico",
        "descripcion": "Manual introductorio de Python: variables, estructuras de control, funciones, "
        "manejo de archivos y buenas prácticas para principiantes.",
        "precio": 14900,
        "capitulos": [
            ("Variables y tipos de datos", [
                "Python es un lenguaje de tipado dinámico: el tipo pertenece al valor y no a la variable. "
                "Los tipos básicos son int, float, str y bool; las colecciones más usadas son list, tuple, dict y set.",
                "Una buena práctica es elegir nombres descriptivos en minúsculas separadas por guion bajo, por ejemplo "
                "total_ventas o fecha_registro, siguiendo la guía de estilo PEP 8.",
            ]),
            ("Estructuras de control", [
                "Las decisiones se expresan con if, elif y else. Los ciclos for recorren cualquier iterable y los ciclos "
                "while se repiten mientras una condición sea verdadera.",
                "Las comprensiones de listas permiten construir colecciones en una sola expresión legible, por ejemplo "
                "[x * 2 for x in datos if x > 0].",
            ]),
            ("Funciones", [
                "Una función se define con def, recibe parámetros y devuelve un valor con return. Los parámetros pueden "
                "tener valores por defecto y aceptar argumentos por nombre.",
                "Documentar cada función con un docstring facilita el mantenimiento y permite generar documentación "
                "automática.",
            ]),
            ("Archivos y excepciones", [
                "La instrucción with abre un archivo y garantiza que se cierre aunque ocurra un error. Las excepciones se "
                "manejan con try, except, else y finally.",
                "Capturar excepciones específicas, en lugar de un except genérico, evita ocultar errores reales del programa.",
            ]),
        ],
    },
    {
        "archivo": "guia_sql_consultas.pdf",
        "nombre": "Guía Práctica de Consultas SQL",
        "descripcion": "Guía de SQL con ejemplos de SELECT, JOIN, agregaciones, subconsultas, índices y "
        "consultas parametrizadas para evitar inyección SQL.",
        "precio": 19900,
        "capitulos": [
            ("Consultas básicas", [
                "SELECT recupera columnas de una o varias tablas. WHERE filtra filas, ORDER BY ordena el resultado y "
                "LIMIT restringe la cantidad de filas devueltas.",
                "Seleccionar solo las columnas necesarias reduce el tráfico y evita exponer datos que la vista no requiere.",
            ]),
            ("Uniones entre tablas", [
                "INNER JOIN devuelve las filas con coincidencia en ambas tablas; LEFT JOIN conserva todas las filas de la "
                "tabla izquierda aunque no tengan pareja.",
                "Las claves foráneas documentan la relación entre tablas y permiten que el motor mantenga la integridad "
                "referencial.",
            ]),
            ("Agregaciones", [
                "COUNT, SUM, AVG, MIN y MAX resumen conjuntos de filas. GROUP BY agrupa por una o más columnas y HAVING "
                "filtra los grupos resultantes.",
            ]),
            ("Seguridad en consultas", [
                "Nunca se deben concatenar valores escritos por el usuario dentro de una sentencia SQL. Las consultas "
                "parametrizadas envían los datos por separado y el motor nunca los interpreta como código.",
                "El principio de privilegio mínimo también aplica a la base de datos: la cuenta de la aplicación solo "
                "debe tener los permisos que realmente utiliza.",
            ]),
        ],
    },
    {
        "archivo": "apuntes_criptografia.pdf",
        "nombre": "Apuntes de Criptografía Aplicada",
        "descripcion": "Apuntes de criptografía: funciones hash, cifrado simétrico y asimétrico, firmas "
        "digitales, certificados X.509 y almacenamiento seguro de contraseñas.",
        "precio": 24900,
        "capitulos": [
            ("Funciones hash", [
                "Una función hash criptográfica como SHA-256 transforma datos de cualquier tamaño en un resumen de 256 bits. "
                "Un cambio mínimo en la entrada produce un resumen completamente distinto.",
                "Los hashes permiten verificar la integridad de archivos: si el resumen calculado coincide con el registrado, "
                "el archivo no fue modificado.",
            ]),
            ("Cifrado simétrico", [
                "AES es el estándar de cifrado simétrico. El modo GCM agrega autenticación: además de ocultar los datos, "
                "detecta cualquier modificación del texto cifrado.",
            ]),
            ("Criptografía de clave pública y firma digital", [
                "En una firma digital se calcula el hash del mensaje y se firma con la clave privada. Cualquiera con la "
                "clave pública puede verificar que el mensaje no cambió y que lo emitió el poseedor de la clave privada.",
                "Esta propiedad aporta no repudio: el emisor no puede negar haber firmado el documento.",
            ]),
            ("Contraseñas", [
                "Las contraseñas no se cifran: se derivan con funciones lentas y con sal como Argon2id o bcrypt, que "
                "encarecen los ataques de diccionario y de fuerza bruta.",
            ]),
            ("Certificados y PKI", [
                "Un certificado X.509 une una clave pública con una identidad y está firmado por una Autoridad "
                "Certificadora. El cliente confía en el servidor porque confía en la CA que firmó su certificado.",
            ]),
        ],
    },
]


def _generar_pdf(ruta: Path, producto: dict):
    estilos = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(ruta), pagesize=letter, leftMargin=2.5 * cm, rightMargin=2.5 * cm,
        topMargin=2.5 * cm, bottomMargin=2.5 * cm,
        title=producto["nombre"], author="Plataforma Segura de Contenido Digital",
        invariant=1,
    )
    historia = [
        Spacer(1, 5 * cm),
        Paragraph(producto["nombre"], estilos["Title"]),
        Paragraph("Material educativo de la Plataforma Segura de Contenido Digital", estilos["Italic"]),
        Spacer(1, 1 * cm),
        Paragraph(producto["descripcion"], estilos["BodyText"]),
        PageBreak(),
    ]
    for numero, (titulo, parrafos) in enumerate(producto["capitulos"], start=1):
        historia.append(Paragraph(f"{numero}. {titulo}", estilos["Heading1"]))
        for p in parrafos:
            historia.append(Paragraph(p, estilos["BodyText"]))
            historia.append(Spacer(1, 0.4 * cm))
        historia.append(PageBreak())
    doc.build(historia)


def generar_productos(carpeta: Path):
    carpeta.mkdir(parents=True, exist_ok=True)
    for p in PRODUCTOS:
        ruta = carpeta / p["archivo"]
        if not ruta.exists():
            _generar_pdf(ruta, p)
            print(f"  [+] Producto generado: productos/{p['archivo']}")
        else:
            print(f"  [=] Producto existente: productos/{p['archivo']}")
    return PRODUCTOS


if __name__ == "__main__":
    generar_productos(Config.PRODUCTS_DIR)
