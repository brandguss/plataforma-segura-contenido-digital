# respaldos/

Aquí se guardan los respaldos cifrados que genera `python scripts/respaldo.py`:

- `respaldo_AAAAMMDD_HHMMSS.psc`: base de datos + productos, empaquetados en `.tar.gz` y cifrados con AES-256-GCM.
- `respaldo_AAAAMMDD_HHMMSS.json`: manifiesto con el SHA-256 del archivo cifrado y los conteos de control.

Los respaldos están excluidos del repositorio (`.gitignore`), porque contienen los datos de la aplicación. Se descifran con `secretos/respaldo.key`, que debe guardarse aparte de los respaldos.
