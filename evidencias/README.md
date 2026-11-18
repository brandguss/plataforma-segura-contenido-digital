# evidencias/

Evidencias de las pruebas obligatorias. Se regeneran con:

```bash
python scripts/generar_evidencias.py
```

| Archivo | Prueba | Contenido |
|---|---|---|
| `resultados_pruebas.md` / `.json` | 1 a 13 | Tabla con la prueba, el resultado esperado, el obtenido y el detalle |
| `salida_pytest.txt` | Todas | Salida completa de `pytest -v` (42 pruebas) |
| `comprobante_original.json` | 7 | Comprobante firmado tal como lo emite la plataforma |
| `verificacion_comprobante_original.txt` | 7 | Resultado: FIRMA VÁLIDA |
| `comprobante_modificado.json` | 8 | El mismo comprobante con `total_centavos` alterado |
| `verificacion_comprobante_modificado.txt` | 8 | Resultado: FIRMA INVÁLIDA |
| `copia_con_fingerprint.pdf` | 9 | Copia descargada con el fingerprint insertado |
| `deteccion_fingerprint.txt` | 9 | Fingerprint recuperado: usuario, orden, producto y capas detectadas |
| `imperceptibilidad_fingerprint.txt` | 9 | Comparación píxel a píxel entre el original y la copia |
| `render_original_pag2.png`, `render_copia_fingerprint_pag2.png` | 9 | Render de la página 2 de ambos archivos (idénticos) |
| `integridad_productos.txt` | 11 | SHA-256 registrado frente al calculado de cada producto |

Las capturas de pantalla del navegador (candado TLS, error de certificado no confiable y páginas 403) se agregan manualmente en esta carpeta durante la demostración.

## Capturas de pantalla (`capturas/`)

| Archivo | Prueba |
|---|---|
| `01_catalogo.png` | Catálogo público |
| `02_login_contrasena_incorrecta.png` | 1. Contraseña incorrecta → acceso rechazado |
| `03_cliente_intenta_admin_403.png` | 2. CLIENTE intenta una función administrativa → 403 |
| `04_carrito.png`, `05_pago_simulado.png`, `06_orden_pagada.png` | Flujo carrito → orden → pago simulado |
| `07_comprobante_firma_valida.png` | 7. Comprobante original → firma válida |
| `08_comprobante_modificado_firma_invalida.png` | 8. Comprobante modificado → firma inválida |
| `09_descarga_no_comprado_403.png` | 10. Descarga de un producto no comprado → 403 |
| `10_operador_productos_integridad.png` | 11. Integridad SHA-256 de los productos (vista del OPERADOR) |
| `11_operador_intenta_roles_403.png` | 3. OPERADOR intenta administrar roles → 403 |
| `12_admin_cambia_rol_permitido.png` | 4. ADMINISTRADOR cambia un rol → permitido |
| `13_admin_fingerprint_detectado.png` | 9. Fingerprint recuperado de la copia descargada |
| `14_admin_bitacora_eventos.png` | Bitácora de eventos de seguridad |
| `15_admin_sesiones.png` | Sesiones activas y revocación |

Las capturas se tomaron con Chrome en modo automatizado, que no muestra la barra de direcciones. El candado TLS (prueba 5) y el error de certificado no confiable (prueba 6) se capturan manualmente en el navegador durante la demostración. Su evidencia automatizada está en `resultados_pruebas.md` y en la salida de `python scripts/probar_tls.py`.
