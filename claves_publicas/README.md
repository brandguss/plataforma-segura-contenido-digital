# claves_publicas/

`firma_publica.pem` es la clave pública RSA-3072 con la que **cualquier persona** puede verificar los comprobantes firmados por la plataforma:

```bash
python scripts/verificar_comprobante.py comprobante_orden_1.json
```

La clave privada correspondiente (`secretos/firma_privada.pem`) solo existe en el servidor y está excluida del repositorio.
