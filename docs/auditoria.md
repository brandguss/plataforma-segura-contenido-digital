# Auditoría de seguridad de la solución

## 1. Datos generales

| Concepto | Descripción |
|---|---|
| Sistema auditado | Plataforma Segura de Venta y Distribución de Contenido Digital |
| Tipo de auditoría | Interna, técnica, de cumplimiento de controles |
| Versión auditada | Rama `main` del repositorio |
| Ambiente | Local: Flask 3, SQLite 3, Python 3.10+, servidor HTTPS en `localhost:8443` |
| Técnicas | Revisión de código, revisión de configuración, pruebas automatizadas y pruebas manuales en el navegador |

## 2. Alcance

**Dentro del alcance**

- Autenticación, sesiones y recuperación de contraseña.
- Autorización por roles (CLIENTE, OPERADOR y ADMINISTRADOR) y control a nivel de objeto.
- Criptografía aplicada: almacenamiento de contraseñas, hashes de archivos, firma digital, cifrado de respaldos y gestión de claves.
- Fingerprinting de productos digitales.
- TLS y PKI local.
- Registro de eventos de seguridad.
- Respaldo y restauración.
- Diseño de la administración remota: SSH, VPN e IPSec, revisado solo como diseño y configuración.

**Fuera del alcance**

- Infraestructura física, sistema operativo del servidor y red real (no hay despliegue productivo).
- Pruebas contra sistemas externos o de terceros (prohibidas por la sección 21).
- Pruebas de carga y denegación de servicio volumétrica.

## 3. Criterios de auditoría

| Id | Criterio | Fuente |
|---|---|---|
| C1 | Requerimientos de seguridad del proyecto (secciones 5 a 19) | Documento del proyecto final |
| C2 | Verificación de autenticación, sesiones, control de acceso, criptografía almacenada y registro | OWASP ASVS 4.0.3, capítulos V2, V3, V4, V6 y V7 |
| C3 | Limitación de intentos de autenticación y autenticación multifactor | NIST SP 800-63B, secciones 4.2 (AAL2) y 5.2.2 (Rate limiting) |
| C4 | Gestión del ciclo de vida de claves criptográficas | NIST SP 800-57 Parte 1 |
| C5 | Principios de privilegio mínimo y separación de responsabilidades | Contenido de la unidad 5 del curso |

## 4. Controles seleccionados y resultado

| # | Control | Criterio | Evidencia | Resultado |
|---|---|---|---|---|
| 1 | Las contraseñas se almacenan solo con Argon2id; no existe columna de contraseña | C1 §7, C2 V2.4 | `test_contrasenas_solo_argon2id`, `schema.sql` | ✅ Cumple |
| 2 | La contraseña incorrecta se rechaza con un mensaje que no revela si el usuario existe | C1 §19, C2 V2 | Prueba obligatoria 1, `test_mensaje_login_no_revela_si_el_usuario_existe` | ✅ Cumple |
| 3 | Hay protección contra fuerza bruta | C3 §5.2.2 | `test_bloqueo_por_intentos_fallidos` | ⚠️ Parcial (**H1**) |
| 4 | Hay autenticación multifactor para cuentas privilegiadas | C3 §4.2 | `test_h2_administrador_entra_con_un_solo_factor` | ❌ No cumple (**H2**) |
| 5 | Las sesiones son aleatorias, expiran, se rotan en el login y son revocables | C2 V3 | `test_cookie_de_sesion_segura`, `test_logout_invalida_la_sesion`, `test_admin_revoca_sesion` | ✅ Cumple |
| 6 | Los roles se aplican con privilegio mínimo | C1 §5, C5 | Pruebas obligatorias 2, 3 y 4 | ✅ Cumple |
| 7 | Un cliente no accede a órdenes ni descargas de otros | C1 §5.1, C2 V4.2 | Prueba obligatoria 10, `test_cliente_no_ve_ordenes_ajenas` | ✅ Cumple |
| 8 | Todo POST exige token CSRF | C2 V4.2.2 | `test_post_sin_csrf_rechazado` | ✅ Cumple |
| 9 | Los comprobantes van firmados y su verificación detecta alteraciones | C1 §11 | Pruebas obligatorias 7 y 8 | ✅ Cumple |
| 10 | Se verifica la integridad SHA-256 de los productos | C1 §8 | Pruebas obligatorias 11 y 12 | ✅ Cumple |
| 11 | El fingerprint es recuperable, imperceptible y robusto | C1 §12 | Prueba obligatoria 9, `test_fingerprint_*`, `test_h3_*` | ⚠️ Parcial (**H3**) |
| 12 | La información sensible está protegida en reposo | C1 §18.5, C2 V6.1 | `test_h4_base_de_datos_legible_sin_clave` | ⚠️ Parcial (**H4**) |
| 13 | Las claves privadas están fuera del código y del repositorio | C1 §11.1 y §13 | `.gitignore`, revisión de código | ✅ Cumple |
| 14 | Las claves privadas están protegidas y separadas según su función | C2 V6.4, C4 | `test_h5_claves_privadas_sin_frase_de_paso_junto_a_la_aplicacion` | ⚠️ Parcial (**H5**) |
| 15 | TLS con certificado de la CA local; un certificado no confiable se rechaza | C1 §13 | Pruebas obligatorias 5 y 6 | ✅ Cumple |
| 16 | Se registran los eventos requeridos con usuario, fecha, resultado y origen | C1 §16, C2 V7 | `test_eventos_requeridos_se_registran` | ✅ Cumple |
| 17 | La bitácora no se puede modificar ni borrar | C2 V7.3 | `test_bitacora_no_se_puede_borrar` | ✅ Cumple |
| 18 | El respaldo se restaura correctamente | C1 §17 | Prueba obligatoria 13 | ✅ Cumple |
| 19 | Los errores no revelan información interna | C2 V7.4 | `test_errores_no_revelan_detalles` | ✅ Cumple |
| 20 | El pago simulado no almacena datos de tarjeta | C1 §10 | `test_pago_simulado_no_guarda_numero_de_tarjeta` | ✅ Cumple |

**Resumen:** 15 controles cumplen, 4 cumplen parcialmente y 1 no cumple.

## 5. Pruebas ejecutadas

```bash
python -m pytest tests -v
```

| Conjunto | Archivo | Pruebas | Resultado |
|---|---|---|---|
| Obligatorias (sección 19) | `tests/test_obligatorias.py` | 13 | 13 pasan |
| Controles complementarios | `tests/test_controles.py` | 23 | 23 pasan |
| Hallazgos de auditoría | `tests/test_auditoria.py` | 6 | 6 pasan (confirman las condiciones encontradas) |

Pruebas manuales complementarias:

1. Navegación con la CA importada: el candado es válido en `https://localhost:8443` y aparece `NET::ERR_CERT_AUTHORITY_INVALID` en `https://localhost:8444`.
2. Cambiar el ID de orden en la URL (`/cliente/orden/N`) con otro cliente: devuelve 403.
3. Alterar con un editor el `total_centavos` de un comprobante descargado: la verificación da "Firma INVÁLIDA".
4. Subir como producto un archivo `.exe` renombrado a `.pdf`: se rechaza por no tener la firma `%PDF-`.

## 6. Escala de riesgo

| Probabilidad \ Impacto | Bajo | Medio | Alto |
|---|---|---|---|
| **Alta** | Medio | Alto | Crítico |
| **Media** | Bajo | Medio | Alto |
| **Baja** | Bajo | Bajo | Medio |

## 7. Hallazgos

### H1. El bloqueo por intentos fallidos es solo por cuenta y no por origen

| Elemento | Descripción |
|---|---|
| **Criterio** | NIST SP 800-63B §5.2.2 pide limitar los intentos fallidos de forma que no se habilite una denegación de servicio contra el usuario legítimo. OWASP ASVS V2.2.1 pide que los controles antiautomatización sean efectivos contra pruebas de credenciales filtradas, fuerza bruta y ataques de bloqueo de cuentas. |
| **Condición** | Tras 5 intentos fallidos, la cuenta se bloquea 15 minutos sin importar quién hizo los intentos. No hay límite por dirección IP: un mismo origen puede probar 4 contraseñas en **cada** cuenta del sistema (rociado de contraseñas) sin bloquear ninguna ni ser frenado. |
| **Causa** | `rutas/publico.py` guarda el contador en `users.failed_attempts`. No existe un contador por origen ni un retardo progresivo. |
| **Riesgo** | **Medio** (probabilidad media, impacto medio). Un atacante puede dejar sin acceso a cualquier usuario conociendo solo su correo, y probar contraseñas comunes en todas las cuentas sin ser detenido. |
| **Evidencia** | `test_h1_bloqueo_por_cuenta_permite_negar_el_servicio`: la víctima recibe 401 con su contraseña correcta. `test_h1_sin_limite_por_ip_permite_rociado_de_contrasenas`: 12 intentos fallidos desde la misma IP, 0 cuentas bloqueadas, y la IP sigue autenticándose. |
| **Recomendación** | 1) Agregar límite por IP con ventana deslizante (por ejemplo `Flask-Limiter`, 10 intentos por minuto por IP). 2) Reemplazar el bloqueo duro por retardo progresivo (1 s, 2 s, 4 s…) o CAPTCHA a partir del tercer intento. 3) Alertar al administrador cuando una IP falle en varias cuentas distintas. |

### H2. Las cuentas privilegiadas se autentican con un solo factor

| Elemento | Descripción |
|---|---|
| **Criterio** | NIST SP 800-63B §4.2: el nivel AAL2, adecuado para cuentas con privilegios, exige dos factores de autenticación distintos. OWASP ASVS V2 recomienda MFA para funciones administrativas. |
| **Condición** | ADMINISTRADOR y OPERADOR inician sesión solo con correo y contraseña. Con la contraseña del administrador se pueden cambiar roles, desactivar cuentas y revocar sesiones. |
| **Causa** | El diseño de autenticación (`rutas/publico.py: login`) no tiene un segundo paso de verificación. |
| **Riesgo** | **Alto** (probabilidad media, impacto alto). Una contraseña de administrador robada por phishing, reutilización o malware da control total sobre los usuarios del sistema. |
| **Evidencia** | `test_h2_administrador_entra_con_un_solo_factor`: con solo la contraseña se obtiene 302 a `/admin/usuarios` y después 200. |
| **Recomendación** | Implementar TOTP (RFC 6238, por ejemplo con `pyotp`) obligatorio para OPERADOR y ADMINISTRADOR. El secreto TOTP se guardaría cifrado con AES-GCM, habría códigos de recuperación de un solo uso y se registrarían los eventos `MFA_SUCCESS` y `MFA_FAILED`. |

### H3. El fingerprint no resiste la conversión del PDF a imagen

| Elemento | Descripción |
|---|---|
| **Criterio** | Sección 12 del proyecto: la técnica debe justificarse en términos de imperceptibilidad, **robustez** y capacidad. |
| **Condición** | El fingerprint resiste quitar los metadatos, extraer páginas y reguardar el archivo. Pero si el PDF se "imprime a imagen" (rasterizado) o se imprime y escanea, el identificador desaparece. También puede eliminarlo alguien que sepa buscar texto con modo de renderizado 3. |
| **Causa** | Las dos capas (texto invisible y metadato) viven en la estructura lógica del PDF, no en la imagen visible de la página. |
| **Riesgo** | **Medio** (probabilidad baja, impacto alto). Un comprador malintencionado con conocimientos técnicos puede redistribuir una copia sin rastro. |
| **Evidencia** | `test_h3_fingerprint_no_sobrevive_rasterizado`: la copia original da `encontrado = True`; la misma copia convertida a imágenes da `encontrado = False`. |
| **Recomendación** | 1) Agregar una tercera capa en el dominio visual: microtexto o marca de agua tenue en el pie de página, o modulación imperceptible del espaciado entre líneas. 2) Agregar una leyenda visible "Copia licenciada a <correo>, orden N" como medida disuasoria. 3) Documentar que ninguna técnica es inmune a fotografiar la pantalla, y apoyarse en la bitácora de descargas. |

### H4. La base de datos se almacena sin cifrado en reposo

| Elemento | Descripción |
|---|---|
| **Criterio** | Requerimiento 5 (sección 18): protección de información sensible. OWASP ASVS V6.1: los datos sensibles deben estar cifrados en reposo. |
| **Condición** | El archivo `base_de_datos/plataforma.db` es legible con cualquier visor de SQLite. Contiene correos, nombres, hashes Argon2id, IPs, fingerprints y la bitácora completa. Los **respaldos** sí van cifrados con AES-256-GCM, pero la base en operación no. |
| **Causa** | SQLite estándar no cifra los datos. Se eligió por simplicidad de despliegue local. |
| **Riesgo** | **Medio** (probabilidad baja, impacto alto). Robar el archivo (equipo perdido, copia indebida, acceso al disco) expone datos personales y permite atacar los hashes sin conexión. Argon2id hace ese ataque costoso, pero no imposible para contraseñas débiles. |
| **Evidencia** | `test_h4_base_de_datos_legible_sin_clave`: el archivo empieza con `SQLite format 3` y contiene en claro `cliente1@demo.local` y `$argon2id$`. |
| **Recomendación** | 1) Cifrar el volumen donde vive la BD (BitLocker o LUKS). 2) O migrar a SQLCipher, o a PostgreSQL con cifrado de disco y TLS hacia la BD. 3) Cifrar a nivel de columna los datos personales que no se usan en búsquedas. |

### H5. Las claves privadas no tienen frase de paso y la CA convive con la aplicación

| Elemento | Descripción |
|---|---|
| **Criterio** | OWASP ASVS V6.4.1: usar una solución de gestión de secretos (bóveda de claves) para crear, almacenar y controlar el acceso a los secretos. NIST SP 800-57: las claves deben protegerse según su función, y la clave de una CA raíz debe mantenerse con el mayor nivel de protección. |
| **Condición** | `firma_privada.pem`, `servidor.key` y `ca.key` están en PKCS#8 **sin cifrar** dentro de `secretos/`, en el mismo equipo que la aplicación. La protección depende solo de los permisos del sistema de archivos (600 y 700). |
| **Causa** | Se priorizó que la aplicación arranque sin intervención humana y que la instalación sea de un solo comando. |
| **Riesgo** | **Alto** (probabilidad baja, impacto alto). Si alguien compromete el servidor, puede emitir comprobantes falsos con firma válida, lo que anula el no repudio. También puede emitir certificados para cualquier nombre con la CA y suplantar el servidor ante clientes que confían en ella. |
| **Evidencia** | `test_h5_claves_privadas_sin_frase_de_paso_junto_a_la_aplicacion`: las tres claves empiezan con `-----BEGIN PRIVATE KEY-----`, no contienen `ENCRYPTED` y la CA está en el mismo directorio que la clave del servidor. |
| **Recomendación** | 1) Sacar `ca.key` del servidor y guardarla fuera de línea (USB cifrada o equipo aislado); usarla solo para emitir o renovar certificados. 2) Guardar la clave de firma en un HSM o servicio KMS, o al menos cifrarla con una frase de paso inyectada por variable de entorno al arrancar. 3) Definir un procedimiento de rotación y revocación (CRL) de la clave de firma y del certificado del servidor. |

## 8. Plan de atención

| Hallazgo | Riesgo | Prioridad | Esfuerzo estimado |
|---|---|---|---|
| H2. MFA para cuentas privilegiadas | Alto | 1 | Medio |
| H5. Protección y separación de claves privadas | Alto | 2 | Bajo (sacar la CA) / Medio (KMS) |
| H1. Límite de intentos por origen | Medio | 3 | Bajo |
| H4. Cifrado en reposo de la BD | Medio | 4 | Bajo (cifrado de volumen) |
| H3. Capa visual del fingerprint | Medio | 5 | Medio |

## 9. Conclusión

La plataforma cumple los controles exigidos por el proyecto, y las 13 pruebas obligatorias pasan. La autorización por roles, la verificación de integridad, la firma digital, el TLS con CA local, la bitácora inmutable y el respaldo cifrado funcionan como se diseñaron.

Los hallazgos no son fallas de lo implementado, sino brechas respecto a estándares externos (NIST y OWASP ASVS): autenticación de un solo factor para cuentas privilegiadas, custodia de claves en el mismo servidor, limitación de intentos solo por cuenta, falta de cifrado de la BD en reposo y la robustez limitada del fingerprint frente al rasterizado. Atender H2 y H5 elevaría más la postura de seguridad, porque protegen las dos piezas de las que depende la confianza en el sistema: la cuenta del administrador y la clave que firma los comprobantes.
