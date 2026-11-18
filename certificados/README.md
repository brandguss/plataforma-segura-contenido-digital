# certificados/

Certificados **públicos** de la PKI local, generados por `python scripts/crear_ca.py`:

| Archivo | Descripción |
|---|---|
| `ca.crt` | CA raíz local (RSA 4096, 10 años). **Es la que se importa como confiable en el navegador.** |
| `servidor.crt` | Certificado del servidor emitido por la CA (RSA 2048, 397 días, SAN `localhost`, `plataforma.local` y `127.0.0.1`) |
| `servidor_cadena.crt` | Servidor + CA: lo que entrega el servidor HTTPS en el puerto 8443 |
| `no_confiable.crt` | Certificado autofirmado sin la CA, usado en el puerto 8444 para la prueba de rechazo |

Las claves privadas correspondientes (`ca.key`, `servidor.key` y `no_confiable.key`) están en `secretos/` y **nunca** se suben al repositorio.

Para inspeccionar un certificado:

```bash
openssl x509 -in certificados/servidor.crt -noout -text
openssl verify -CAfile certificados/ca.crt certificados/servidor.crt
```
