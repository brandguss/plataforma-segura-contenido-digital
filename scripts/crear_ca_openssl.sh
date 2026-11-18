#!/usr/bin/env bash
# =====================================================================
# Equivalente con OpenSSL de scripts/crear_ca.py (Linux / macOS / Git Bash).
# Genera la CA local, el certificado del servidor firmado por la CA y un
# certificado autofirmado no confiable para la prueba de rechazo.
#
# Uso (desde la raíz del repositorio):   bash scripts/crear_ca_openssl.sh
# =====================================================================
set -euo pipefail

CERTS="certificados"
SECRETOS="secretos"
mkdir -p "$CERTS" "$SECRETOS"
umask 077   # todo lo que se cree en esta sesión queda solo para el dueño

SUJETO_BASE="/C=MX/ST=Chihuahua/L=Ciudad Juarez/O=Plataforma Segura de Contenido Digital"

# --- 1. CA raíz local (RSA 4096, 10 años) ------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$SECRETOS/ca.key"
openssl req -x509 -new -key "$SECRETOS/ca.key" -sha256 -days 3650 \
  -subj "$SUJETO_BASE/OU=Autoridad Certificadora/CN=CA Local Plataforma Segura" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$CERTS/ca.crt"

# --- 2. Certificado del servidor (RSA 2048, 397 días, SAN) -------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SECRETOS/servidor.key"
openssl req -new -key "$SECRETOS/servidor.key" \
  -subj "$SUJETO_BASE/OU=Servidor de aplicacion/CN=localhost" \
  -out "$SECRETOS/servidor.csr"

cat > "$SECRETOS/servidor.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:plataforma.local,IP:127.0.0.1
EOF

openssl x509 -req -in "$SECRETOS/servidor.csr" -CA "$CERTS/ca.crt" -CAkey "$SECRETOS/ca.key" \
  -CAcreateserial -days 397 -sha256 -extfile "$SECRETOS/servidor.ext" -out "$CERTS/servidor.crt"
cat "$CERTS/servidor.crt" "$CERTS/ca.crt" > "$CERTS/servidor_cadena.crt"

# --- 3. Certificado autofirmado NO confiable ---------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$SECRETOS/no_confiable.key" -sha256 -days 397 \
  -subj "$SUJETO_BASE/OU=Certificado NO confiable (autofirmado)/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:plataforma.local,IP:127.0.0.1" \
  -out "$CERTS/no_confiable.crt"

chmod 600 "$SECRETOS"/*.key
rm -f "$SECRETOS/servidor.csr" "$SECRETOS/servidor.ext"

# --- Verificación de la cadena -----------------------------------------
openssl verify -CAfile "$CERTS/ca.crt" "$CERTS/servidor.crt"
openssl verify -CAfile "$CERTS/ca.crt" "$CERTS/no_confiable.crt" || echo "OK: el certificado autofirmado NO es válido para la CA local"
