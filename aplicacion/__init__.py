"""
Fábrica de la aplicación Flask.

Ejecutar el servidor HTTPS:   python -m aplicacion
"""
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, g, render_template, request

from . import db
from .config import Config
from .criptografia import leer_secreto
from .seguridad import (
    CSRF_COOKIE,
    cargar_usuario,
    csrf_token,
    formato_moneda,
    get_setting,
    validar_csrf,
)


def create_app(config_extra=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_extra:
        app.config.update(config_extra)

    # Clave de la aplicación: se lee de secretos/, nunca está en el código fuente.
    app.config["SECRET_KEY"] = leer_secreto(app.config["SECRETS_DIR"] / app.config["APP_SECRET"])

    _configurar_bitacora_errores(app)
    db.init_app(app)

    # --- Middleware de seguridad ------------------------------------------
    app.before_request(cargar_usuario)
    app.before_request(validar_csrf)

    @app.after_request
    def cabeceras_seguridad(respuesta):
        # HSTS: el navegador solo usará HTTPS con este sitio durante 1 año
        respuesta.headers["Strict-Transport-Security"] = "max-age=31536000"
        # CSP: solo recursos propios, sin scripts en línea ni marcos externos
        respuesta.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        respuesta.headers["X-Content-Type-Options"] = "nosniff"
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Referrer-Policy"] = "no-referrer"
        respuesta.headers["Cache-Control"] = "no-store"
        nueva = g.get("csrf_nueva_cookie")
        if nueva:
            respuesta.set_cookie(
                CSRF_COOKIE, nueva, secure=True, httponly=True, samesite="Strict"
            )
        return respuesta

    # --- Plantillas -------------------------------------------------------
    app.jinja_env.globals["csrf_token"] = csrf_token
    # Longitud mínima vigente (la define el ADMINISTRADOR) para el verificador de contraseñas
    app.jinja_env.globals["minimo_password"] = lambda: get_setting("password_min_length")
    app.jinja_env.filters["moneda"] = formato_moneda

    @app.context_processor
    def usuario_actual():
        return {"usuario": g.get("user")}

    # --- Rutas ------------------------------------------------------------
    from .rutas import admin, cliente, operador, publico

    app.register_blueprint(publico.bp)
    app.register_blueprint(cliente.bp)
    app.register_blueprint(operador.bp)
    app.register_blueprint(admin.bp)

    _registrar_errores(app)
    return app


def _configurar_bitacora_errores(app):
    """Los detalles técnicos de los errores van a un archivo, nunca al usuario."""
    ruta = app.config["LOG_FILE"]
    ruta.parent.mkdir(parents=True, exist_ok=True)
    manejador = RotatingFileHandler(ruta, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    manejador.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    manejador.setLevel(logging.WARNING)
    app.logger.addHandler(manejador)


def _registrar_errores(app):
    """Páginas de error genéricas: no revelan rutas, versiones ni trazas."""
    mensajes = {
        400: "Solicitud no válida.",
        403: "No tienes permiso para realizar esta acción.",
        404: "El recurso solicitado no existe.",
        405: "Método no permitido.",
        413: "El archivo excede el tamaño permitido.",
        500: "Ocurrió un error interno. El incidente fue registrado.",
    }

    def manejar(error):
        codigo = getattr(error, "code", 500) or 500
        if codigo == 500:
            app.logger.exception("Error interno en %s", request.path)
        return render_template("errores/error.html", codigo=codigo, mensaje=mensajes.get(codigo, "Error.")), codigo

    for codigo in mensajes:
        app.register_error_handler(codigo, manejar)
    app.register_error_handler(Exception, manejar)
