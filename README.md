# Plataforma Segura de Venta y Distribución de Contenido Digital

Aplicación web de comercio electrónico para vender y distribuir productos digitales en PDF (manuales, guías y apuntes). Cada copia descargada queda ligada al comprador y a la orden mediante **fingerprinting**. La aplicación aplica criptografía, HTTPS/TLS con una CA local, control de acceso por roles, contraseñas con Argon2id, firma digital de comprobantes, bitácora de eventos de seguridad, y respaldo y restauración cifrados.

> Proyecto académico. Los pagos son **simulados**: no se usan tarjetas, cuentas ni datos personales reales.

---

## Contenido

1. [Tecnologías](#tecnologías)
2. [Estructura del repositorio](#estructura-del-repositorio)
3. [Manual de instalación y ejecución](#manual-de-instalación-y-ejecución)
4. [Cuentas de prueba](#cuentas-de-prueba)
5. [Funciones por rol](#funciones-por-rol)
6. [Pruebas y evidencias](#pruebas-y-evidencias)
7. [Scripts disponibles](#scripts-disponibles)
8. [Documentación](#documentación)
9. [Manejo de claves privadas](#manejo-de-claves-privadas)

---

## Tecnologías

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.10 o superior |
| Framework web | Flask 3 |
| Base de datos | SQLite 3 (relacional, 12 tablas) |
| Contraseñas | Argon2id (`argon2-cffi`) |
| Criptografía | `cryptography`: RSA-PSS/SHA-256, AES-256-GCM, X.509 |
| Fingerprinting PDF | `pypdf` + `reportlab` |
| Verificación visual | `pypdfium2` + Pillow |
| Pruebas | `pytest` |

No se implementó ningún algoritmo criptográfico ni protocolo (TLS, IPSec) desde cero. Todo usa bibliotecas probadas.

## Estructura del repositorio

```
plataforma-segura-contenido-digital/
├── aplicacion/                  Código fuente de la app Flask
│   ├── __init__.py              Fábrica de la app, cabeceras de seguridad, manejo de errores
│   ├── __main__.py              Servidor HTTPS (TLS 1.2+)  ->  python -m aplicacion
│   ├── config.py                Configuración y rutas
│   ├── db.py                    Conexión a la BD
│   ├── seguridad.py             Argon2id, sesiones, CSRF, roles, bitácora, validación
│   ├── criptografia.py          SHA-256, firma RSA-PSS, AES-256-GCM
│   ├── fingerprint.py           Inserción y extracción del fingerprint en PDF
│   ├── servicios.py             Comprobantes firmados y copias personalizadas
│   ├── rutas/                   publico.py, cliente.py, operador.py, admin.py
│   ├── templates/               Vistas HTML
│   └── static/estilos.css
├── base_de_datos/
│   ├── schema.sql               Script de creación de la base de datos
│   ├── crear_bd.py              Crea el esquema
│   └── datos_prueba.py          Usuarios y productos de prueba
├── certificados/                Certificados PÚBLICOS: CA, servidor, no confiable
├── claves_publicas/             Clave pública para verificar firmas de comprobantes
├── scripts/                     Instalación, PKI, respaldo, restauración y verificaciones
├── productos/                   Productos digitales originales (PDF)
├── respaldos/                   Respaldos cifrados (excluidos del repositorio)
├── evidencias/                  Evidencias de las pruebas obligatorias
├── docs/                        Arquitectura de seguridad, SSH/VPN/IPSec, auditoría, demo
├── tests/                       Pruebas automáticas (43 en total, 13 obligatorias)
├── secretos/                    CLAVES PRIVADAS (excluida por .gitignore, se genera al instalar)
├── requirements.txt
└── README.md
```

---

## Manual de instalación y ejecución

### 1. Requisitos

- Python 3.10 o superior. En Windows, comprueba con `py --version`; en Linux o macOS, con `python3 --version`.
- Git.

### 2. Clonar e instalar dependencias

**Windows (PowerShell):**

```powershell
git clone https://github.com/brandguss/plataforma-segura-contenido-digital.git
cd plataforma-segura-contenido-digital
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS:**

```bash
git clone https://github.com/brandguss/plataforma-segura-contenido-digital.git
cd plataforma-segura-contenido-digital
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Si PowerShell bloquea `Activate.ps1`, ejecuta una vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### 3. Instalar el sistema (claves, PKI, productos y base de datos)

```bash
python scripts/instalar.py
```

Este comando genera:

- En `secretos/`: claves privadas de firma, CA y servidor, más las claves del fingerprint, del respaldo y de la aplicación.
- En `certificados/`: la CA local, el certificado del servidor y el certificado no confiable.
- En `productos/`: los 3 PDF de prueba.
- En `base_de_datos/plataforma.db`: el esquema y los datos de prueba.

Es idempotente: si algo ya existe, se conserva.

### 4. Confiar en la CA local

Para que el navegador acepte el certificado del servidor, importa `certificados/ca.crt` como **autoridad raíz de confianza**:

| Sistema / navegador | Cómo hacerlo |
|---|---|
| Windows (Chrome y Edge) | `certutil -addstore -user Root certificados\ca.crt` y luego reinicia el navegador |
| Firefox | Ajustes → Privacidad y seguridad → Certificados → Ver certificados → Autoridades → Importar → `ca.crt` → marcar "Confiar en esta CA para identificar sitios web" |
| Linux (Debian/Ubuntu) | `sudo cp certificados/ca.crt /usr/local/share/ca-certificates/psc-ca.crt && sudo update-ca-certificates` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certificados/ca.crt` |

### 5. Ejecutar

```bash
python -m aplicacion
```

Abre **https://localhost:8443**. Debe aparecer el candado sin advertencias.

Para la prueba del certificado no confiable, en otra terminal:

```bash
python -m aplicacion --no-confiable
```

Abre **https://localhost:8444**. El navegador mostrará `NET::ERR_CERT_AUTHORITY_INVALID`. Para comprobar ambos casos desde la terminal:

```bash
python scripts/probar_tls.py
```

### 6. Recuperación de contraseña

No se envían correos reales. El enlace temporal (15 minutos, un solo uso) se guarda como archivo de texto en `correo_simulado/`.

---

## Cuentas de prueba

| Rol | Correo | Contraseña |
|---|---|---|
| ADMINISTRADOR | `admin@demo.local` | `Admin#2026Seguro` |
| OPERADOR | `operador@demo.local` | `Operador#2026Seguro` |
| CLIENTE | `cliente1@demo.local` | `Cliente#2026Uno` |
| CLIENTE | `cliente2@demo.local` | `Cliente#2026Dos` |

Las contraseñas nuevas deben tener al menos 10 caracteres, una mayúscula, una minúscula y un número. Los formularios de registro, perfil y restablecimiento muestran estos requisitos en vivo.

Tarjetas **de prueba** para el pago simulado (el número nunca se almacena):

| Tarjeta | Resultado |
|---|---|
| `4242 4242 4242 4242` | Pago aprobado |
| `4000 0000 0000 0002` | Pago rechazado |

---

## Funciones por rol

| Función | Público | CLIENTE | OPERADOR | ADMINISTRADOR |
|---|:-:|:-:|:-:|:-:|
| Catálogo y detalle de producto | ✔ | ✔ | ✔ | ✔ |
| Registro, inicio de sesión y recuperación de contraseña | ✔ | | | |
| Perfil, carrito, órdenes y pago simulado | | ✔ | | |
| Comprobante firmado y verificación de firma | | ✔ | | |
| Descargar productos **propios** con fingerprint | | ✔ | | |
| Alta, edición, precios y activación de productos | | | ✔ | |
| Consultar y actualizar órdenes | | | ✔ | |
| Usuarios, roles y activar o desactivar cuentas | | | | ✔ |
| Revocar sesiones | | | | ✔ |
| Eventos de seguridad y operaciones | | | | ✔ |
| Configuración de seguridad | | | | ✔ |
| Detectar el fingerprint de una copia sospechosa | | | | ✔ |
| Ver contraseñas o claves privadas | ✘ | ✘ | ✘ | ✘ |

---

## Pruebas y evidencias

```bash
python -m pytest tests -v             # 43 pruebas (13 obligatorias + 24 de controles + 6 de auditoría)
python scripts/generar_evidencias.py  # ejecuta todo y regenera evidencias/
```

`evidencias/resultados_pruebas.md` contiene la tabla de las 13 pruebas obligatorias con el resultado esperado, el obtenido y el detalle de cada una.

| # | Prueba | Resultado esperado | Evidencia |
|---|---|---|---|
| 1 | Contraseña incorrecta | Acceso rechazado | `resultados_pruebas.md` |
| 2 | CLIENTE intenta una función administrativa | Acceso rechazado | `resultados_pruebas.md` |
| 3 | OPERADOR intenta cambiar roles | Acceso rechazado | `resultados_pruebas.md` |
| 4 | ADMINISTRADOR autorizado | Operación permitida | `resultados_pruebas.md` |
| 5 | Certificado TLS correcto | Conexión aceptada | `resultados_pruebas.md` y `scripts/probar_tls.py` |
| 6 | Certificado no confiable | Conexión rechazada | `resultados_pruebas.md` y `scripts/probar_tls.py` |
| 7 | Comprobante original | Firma válida | `comprobante_original.json`, `verificacion_comprobante_original.txt` |
| 8 | Comprobante modificado | Firma inválida | `comprobante_modificado.json`, `verificacion_comprobante_modificado.txt` |
| 9 | Producto descargado | Fingerprint recuperable | `copia_con_fingerprint.pdf`, `deteccion_fingerprint.txt`, `imperceptibilidad_fingerprint.txt` |
| 10 | CLIENTE descarga producto no comprado | Acceso rechazado | `resultados_pruebas.md` |
| 11 | Archivo original | Hash esperado | `integridad_productos.txt` |
| 12 | Archivo modificado | Hash diferente | `resultados_pruebas.md` |
| 13 | Restauración de respaldo | Información recuperada | `resultados_pruebas.md` |

---

## Scripts disponibles

| Comando | Función |
|---|---|
| `python scripts/instalar.py` | Instalación completa (claves, PKI, productos y BD) |
| `python scripts/crear_ca.py [--forzar]` | CA local, certificado del servidor y certificado no confiable |
| `bash scripts/crear_ca_openssl.sh` | Lo mismo, con comandos OpenSSL |
| `python scripts/generar_claves.py` | Claves de firma, fingerprint, respaldo y aplicación |
| `python base_de_datos/crear_bd.py` | Crea el esquema de la base de datos |
| `python base_de_datos/datos_prueba.py` | Carga los usuarios y productos de prueba |
| `python scripts/respaldo.py` | Respaldo cifrado (AES-256-GCM) de la BD y los productos |
| `python scripts/restaurar.py [archivo]` | Restaura y verifica un respaldo (por defecto el más reciente) |
| `python scripts/verificar_comprobante.py archivo.json` | Verifica la firma de un comprobante sin usar la app |
| `python scripts/detectar_fingerprint.py archivo.pdf` | Extrae el fingerprint e identifica usuario y orden |
| `python scripts/verificar_hash.py [archivo]` | Verifica la integridad SHA-256 de los productos |
| `python scripts/probar_tls.py` | Prueba la conexión con el certificado confiable y con el no confiable |
| `python scripts/generar_evidencias.py` | Ejecuta las pruebas y regenera las evidencias |

### Demostración de respaldo y restauración

```bash
python scripts/respaldo.py
# Simular la pérdida del ambiente (detén el servidor antes):
#   Windows:  del base_de_datos\plataforma.db ; del productos\*.pdf
#   Linux:    rm base_de_datos/plataforma.db productos/*.pdf
python scripts/restaurar.py
python -m aplicacion       # los usuarios, productos y órdenes siguen ahí
```

---

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/arquitectura_seguridad.md`](docs/arquitectura_seguridad.md) | Arquitectura, servicios de seguridad, criptografía, gestión de claves y fingerprinting |
| [`docs/despliegue_ssh_vpn_ipsec.md`](docs/despliegue_ssh_vpn_ipsec.md) | Administración por SSH, arquitectura con VPN y uso de IPSec en modo túnel |
| [`docs/config/`](docs/config/) | `sshd_config` endurecido y ejemplos de WireGuard y strongSwan |
| [`docs/auditoria.md`](docs/auditoria.md) | Auditoría de la propia solución: alcance, criterios, controles, pruebas y hallazgos |
| [`docs/guion_demostracion.md`](docs/guion_demostracion.md) | Guion paso a paso para la demostración final |

---

## Manejo de claves privadas

- Todas las claves privadas viven en `secretos/`, que está excluida por `.gitignore` y tiene permisos `700`; cada archivo tiene `600`.
- El código fuente **no contiene** claves: las lee de `secretos/` al arrancar.
- Al repositorio solo se suben `certificados/*.crt` y `claves_publicas/firma_publica.pem`, que son públicos.
- Si clonas el repositorio sin la carpeta `secretos/`, `python scripts/instalar.py` genera una PKI y claves nuevas. Después ejecuta `python scripts/generar_evidencias.py` para que las evidencias queden firmadas con tus claves.
