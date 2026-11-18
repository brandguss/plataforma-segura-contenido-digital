# Guion de la demostración final

Duración estimada: 15 a 20 minutos. Antes de empezar:

```bash
python scripts/instalar.py
python -m aplicacion                 # terminal 1 -> https://localhost:8443
python -m aplicacion --no-confiable  # terminal 2 -> https://localhost:8444
```

Ten importada `certificados/ca.crt` en el navegador. Usa una ventana normal y una de incógnito para tener dos usuarios a la vez.

---

## Parte 1. TLS y PKI (Unidad 4)

1. Abrir `https://localhost:8443` y hacer clic en el **candado**. Mostrar el certificado emitido por "CA Local Plataforma Segura", el SAN `localhost` y la vigencia de 397 días.
2. Abrir `https://localhost:8444`. El navegador muestra **`NET::ERR_CERT_AUTHORITY_INVALID`**.
3. En una terminal, ejecutar `python scripts/probar_tls.py`. El puerto 8443 da ACEPTADA (TLSv1.3) y el 8444 da RECHAZADA (CERTIFICATE_VERIFY_FAILED).
4. Mostrar que `secretos/` **no** está en GitHub (`.gitignore`) y que `certificados/` solo tiene archivos `.crt`.

## Parte 2. Autenticación y roles (Unidades 2 y 5)

5. Iniciar sesión como `cliente1@demo.local` con una contraseña **incorrecta**. Aparece el mensaje genérico (prueba 1).
6. Entrar con `Cliente#2026Uno`. En la barra de direcciones, ir a `https://localhost:8443/admin/usuarios`. Resultado: **403** (prueba 2).
7. En incógnito, entrar como `operador@demo.local` e ir a `/admin/usuarios`. Resultado: **403** (prueba 3).
8. Salir y entrar como `admin@demo.local`. En **Usuarios**, cambiar el rol de `cliente2` a OPERADOR y regresarlo a CLIENTE: la operación se permite (prueba 4). Mostrar que **no** se ve ninguna contraseña ni hash.

## Parte 3. Compra, firma digital y fingerprint (Unidades 2 y 3)

9. Como `cliente1`, agregar el **Manual de Python Básico** al carrito, crear la orden y pagar con `4242 4242 4242 4242`.
10. Abrir el **comprobante**: aparece "Firma digital VÁLIDA". Descargar el `.json`.
11. Ir a **Verificar firma**, subir el `.json` y obtener **VÁLIDA** (prueba 7). Abrir el `.json` en el Bloc de notas, cambiar `"total_centavos": 14900` por `100`, guardar y volver a verificar: **INVÁLIDA** (prueba 8).
12. Verificar fuera de la app: `python scripts/verificar_comprobante.py comprobante_orden_1.json`.
13. Desde la orden, **descargar la copia personalizada**. Abrirla: se ve igual al original.
14. Como `admin`, ir a **Fingerprint** y subir la copia. Se recupera el usuario `cliente1`, la orden y la fecha de la descarga (prueba 9). También funciona desde la terminal: `python scripts/detectar_fingerprint.py "%USERPROFILE%\Downloads\orden1_producto1.pdf"`.
15. Como `cliente1`, cambiar la URL a `/cliente/descargar/1/2` (un producto que no compró). Resultado: **403** (prueba 10).

## Parte 4. Integridad de archivos (Unidad 2)

16. Ejecutar `python scripts/verificar_hash.py`: los 3 productos dan OK (prueba 11).
17. Abrir `productos/manual_python_basico.pdf` con un editor de texto, agregar un carácter al final y guardar. Volver a ejecutar `verificar_hash.py`: da **ALTERADO** (prueba 12). Como cliente, intentar la descarga: la app la bloquea y registra `INTEGRITY_FAILED`. Después, restaurar el archivo con `git checkout productos/manual_python_basico.pdf`.

## Parte 5. Bitácora y disponibilidad (Unidades 1 y 5)

18. Como `admin`, ir a **Eventos**: aparecen LOGIN_FAILED, ACCESS_DENIED, ORDER_CREATED, PAYMENT_APPROVED, SIGNATURE_CREATED, FINGERPRINT_CREATED, DOWNLOAD, ROLE_CHANGED e INTEGRITY_FAILED, con usuario, fecha, resultado e IP.
19. Detener el servidor y ejecutar `python scripts/respaldo.py`.
20. Simular la pérdida del ambiente: `del base_de_datos\plataforma.db` y `del productos\*.pdf`.
21. Ejecutar `python scripts/restaurar.py`. El resultado muestra `"correcto": true` con los conteos.
22. Levantar el servidor y entrar como `cliente1`: la orden y el comprobante siguen ahí (prueba 13).

## Parte 6. Pruebas automáticas y auditoría

23. Ejecutar `python -m pytest tests -v`: 42 pruebas pasan.
24. Mostrar `evidencias/resultados_pruebas.md` con la tabla de las 13 pruebas obligatorias.
25. Presentar `docs/auditoria.md`: el alcance, los criterios, los 20 controles y los 5 hallazgos con su prueba de evidencia.
26. Presentar `docs/despliegue_ssh_vpn_ipsec.md`: el diagrama con la VPN antes de SSH y el uso de IPSec en modo túnel entre sedes.

---

## Respuestas rápidas para preguntas frecuentes

| Pregunta | Respuesta |
|---|---|
| ¿Por qué Argon2id y no SHA-256 para las contraseñas? | SHA-256 es rápido, y eso facilita la fuerza bruta. Argon2id es lento a propósito y usa 64 MiB de memoria por intento, lo que encarece los ataques con GPU. |
| ¿Dónde está la sal? | Dentro del propio hash (`$argon2id$v=19$m=65536,t=3,p=4$<sal>$<hash>`). La biblioteca la genera y la lee. |
| ¿El administrador puede ver contraseñas? | No. Solo existen hashes, y ni siquiera se seleccionan en las consultas de administración. |
| ¿Qué pasa si alguien cambia el fingerprint para culpar a otro usuario? | El identificador lleva un HMAC con una clave secreta. Si se modifica, la etiqueta no coincide y se marca como falsificado. |
| ¿Por qué se guarda el precio en `order_items`? | Para que las órdenes históricas conserven el precio pagado aunque el operador lo cambie después. |
| ¿Qué servicio aporta la firma digital? | Integridad y no repudio del emisor: solo quien tiene la clave privada pudo firmar el comprobante. |
| ¿Por qué VPN y además SSH? | Defensa en profundidad: SSH ni siquiera es visible desde Internet, y robar una sola credencial no alcanza. |
