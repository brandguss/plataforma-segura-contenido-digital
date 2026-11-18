# Resultados de las pruebas obligatorias

Generado automáticamente por `pytest` el 2026-11-17 21:08:08.

| # | Prueba | Resultado esperado | Resultado obtenido | Estado | Detalle |
|---|--------|--------------------|--------------------|--------|---------|
| 1 | Contraseña incorrecta | Acceso rechazado | HTTP 401; /cliente/ordenes redirige a login | ✅ PASA | Evento LOGIN_FAILED registrado: contraseña incorrecta (intento 1) |
| 2 | CLIENTE intenta una función administrativa | Acceso rechazado | GET /admin/usuarios → 403; POST cambio de rol → 403 | ✅ PASA | También /operador/productos → 403. Rol sin cambios: CLIENTE. Eventos ACCESS_DENIED: 3 |
| 3 | OPERADOR intenta cambiar roles | Acceso rechazado | HTTP 403 | ✅ PASA | El rol del usuario 3 sigue siendo CLIENTE; evento ACCESS_DENIED registrado |
| 4 | ADMINISTRADOR autorizado | Operación permitida | HTTP 302; rol nuevo = OPERADOR | ✅ PASA | Evento ROLE_CHANGED: usuario=cliente1@demo.local CLIENTE->OPERADOR |
| 5 | Certificado TLS correcto | Conexión aceptada | TLSv1.3 · TLS_AES_256_GCM_SHA384 · HTTP/1.1 200 OK | ✅ PASA | Cadena validada contra certificados/ca.crt; emisor: CA Local Plataforma Segura; hostname: localhost |
| 6 | Certificado no confiable | Conexión rechazada | Handshake TLS abortado por el cliente | ✅ PASA | CERTIFICATE_VERIFY_FAILED: self-signed certificate |
| 7 | Comprobante original | Firma digital válida | FIRMA VÁLIDA (biblioteca y página /cliente/verificar) | ✅ PASA | Orden 1, RSA-PSS-SHA256, key_id b96432894e7a8cf2669b37c3d2b5163a. Archivo: evidencias/comprobante_original.json |
| 8 | Comprobante modificado | Firma digital inválida | FIRMA INVÁLIDA (biblioteca y página web) | ✅ PASA | Se cambió total_centavos de 14900 a 100. Archivo: evidencias/comprobante_modificado.json |
| 9 | Producto descargado | Fingerprint recuperable | Recuperado SCD1-3322cbf1-U3-O1-P2-b901243f1201d16f | ✅ PASA | usuario=3 orden=1 producto=2; HMAC válido; capas: metadato=True, texto en 5/5 páginas. Archivo: evidencias/copia_con_fingerprint.pdf |
| 10 | CLIENTE intenta descargar producto no comprado | Acceso rechazado | Producto fuera de la orden → 403; orden de otro cliente → 403 | ✅ PASA | 2 eventos DOWNLOAD con resultado DENEGADO |
| 11 | Archivo original | Hash esperado | SHA-256 coincide | ✅ PASA | manual_python_basico.pdf<br>registrado: 6564b287db49e442a47669329688ac05e5ac7dd32483001c6dd674e17d1186f1<br>calculado:  6564b287db49e442a47669329688ac05e5ac7dd32483001c6dd674e17d1186f1 |
| 12 | Archivo modificado | Hash diferente | SHA-256 distinto; descarga bloqueada | ✅ PASA | registrado: 6564b287db49e442a47669329688ac05e5ac7dd32483001c6dd674e17d1186f1<br>calculado:  5722830bff7d67b68dfdea29b27bcc29ea334764f52bce343346f69daee7cfed<br>Evento INTEGRITY_FAILED registrado |
| 13 | Restauración de respaldo | Información crítica recuperada | Usuarios, productos y órdenes recuperados | ✅ PASA | Respaldo AES-256-GCM respaldo_20261118_040808.psc. Antes: users=4, products=3, orders=2, payments=2, receipts=2. Después: users=4, products=3, orders=2, payments=2, receipts=2. Productos íntegros: 3/3 |
