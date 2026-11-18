"""
Configuración central de la aplicación.

Todas las rutas se calculan a partir de la raíz del repositorio, de modo que
el proyecto funcione igual en Windows y en Linux. Los secretos (claves privadas,
clave de sesión, clave de respaldo) viven en la carpeta secretos/, que está
excluida del repositorio mediante .gitignore.

Cualquier valor puede sobrescribirse con variables de entorno, útil para las
pruebas automáticas (que usan un directorio temporal).
"""
import os
from pathlib import Path

# Raíz del repositorio (carpeta que contiene aplicacion/, scripts/, etc.)
BASE_DIR = Path(__file__).resolve().parent.parent


def _ruta(variable, por_defecto):
    """Devuelve la ruta indicada en una variable de entorno o la ruta por defecto."""
    return Path(os.environ.get(variable, por_defecto))


class Config:
    # --- Rutas -------------------------------------------------------------
    BASE_DIR = BASE_DIR
    DB_PATH = _ruta("PSC_DB_PATH", BASE_DIR / "base_de_datos" / "plataforma.db")
    SCHEMA_PATH = BASE_DIR / "base_de_datos" / "schema.sql"
    PRODUCTS_DIR = _ruta("PSC_PRODUCTS_DIR", BASE_DIR / "productos")
    SECRETS_DIR = _ruta("PSC_SECRETS_DIR", BASE_DIR / "secretos")
    CERTS_DIR = _ruta("PSC_CERTS_DIR", BASE_DIR / "certificados")
    PUBLIC_KEYS_DIR = _ruta("PSC_PUBLIC_KEYS_DIR", BASE_DIR / "claves_publicas")
    BACKUPS_DIR = _ruta("PSC_BACKUPS_DIR", BASE_DIR / "respaldos")
    OUTBOX_DIR = _ruta("PSC_OUTBOX_DIR", BASE_DIR / "correo_simulado")
    LOG_FILE = _ruta("PSC_LOG_FILE", BASE_DIR / "base_de_datos" / "errores.log")

    # --- Archivos de claves -----------------------------------------------
    # Privadas (fuera del repositorio, permisos restringidos)
    SIGNING_PRIVATE_KEY = "firma_privada.pem"
    FINGERPRINT_KEY = "fingerprint.key"
    BACKUP_KEY = "respaldo.key"
    APP_SECRET = "app_secret.key"
    SERVER_KEY = "servidor.key"
    # Públicas (sí se distribuyen)
    SIGNING_PUBLIC_KEY = "firma_publica.pem"

    # --- Sesión -------------------------------------------------------------
    AUTH_COOKIE_NAME = "psc_sid"          # cookie con el token de sesión del servidor
    SESSION_COOKIE_NAME = "psc_flash"     # cookie firmada de Flask (solo mensajes flash)
    SESSION_COOKIE_SECURE = True          # solo viaja por HTTPS
    SESSION_COOKIE_HTTPONLY = True        # inaccesible desde JavaScript
    SESSION_COOKIE_SAMESITE = "Strict"    # mitiga CSRF
    SESSION_ABSOLUTE_HOURS = 8            # vida máxima de una sesión

    # --- Seguridad ----------------------------------------------------------
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB máximo por petición (subida de PDF)
    RESET_TOKEN_MINUTES = 15               # vigencia del token de recuperación

    # Valores por defecto de la tabla settings (el ADMINISTRADOR puede cambiarlos)
    DEFAULT_SETTINGS = {
        "max_failed_logins": "5",          # intentos antes del bloqueo temporal
        "lockout_minutes": "15",           # duración del bloqueo
        "session_idle_minutes": "30",      # cierre por inactividad
        "password_min_length": "10",       # longitud mínima de contraseña
    }

    # Tarjetas de PRUEBA para el pago simulado (no son tarjetas reales).
    # Nunca se almacena el número capturado: solo el resultado.
    TEST_CARD_APPROVED = "4242424242424242"
    TEST_CARD_DECLINED = "4000000000000002"

    # --- Servidor HTTPS -----------------------------------------------------
    HOST = os.environ.get("PSC_HOST", "127.0.0.1")
    PORT = int(os.environ.get("PSC_PORT", "8443"))
    UNTRUSTED_PORT = int(os.environ.get("PSC_UNTRUSTED_PORT", "8444"))
    # URL pública fija para enlaces enviados por correo (evita inyección de cabecera Host)
    PUBLIC_BASE_URL = os.environ.get("PSC_PUBLIC_BASE_URL", f"https://localhost:{PORT}")

    DEBUG = False
    TESTING = False
