#!/usr/bin/env bash
# Regenera los certificados de ejemplo (entidad ficticia) con OpenSSL >= 3.5.
# Las claves privadas se crean en un directorio temporal y se borran al terminar.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="$ROOT/samples"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cd "$T"
O="/C=ES/O=Banco Ficticio Atlantida S.A. (EJEMPLO)"
HDR="# DATOS DE EJEMPLO - Banco Ficticio Atlántida S.A. (entidad inventada, no real)"
leafext() { printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,%s\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$2" "$1" > "$1.ext"; }
pem() { { echo "$HDR"; cat "$1"; } > "$S/$2"; }

# Raíz RSA-4096
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "$O/CN=Atlantida Root CA EJEMPLO" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
pem ca.pem atlantida-root-ca.pem

issue() { # nombre clave_args usos [digest]
  openssl genpkey $2 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -subj "$O/CN=$1" -out "$1.csr"
  leafext "$1" "$3"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -${4:-sha256} -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}
issue banca-online.atlantida.example "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" "digitalSignature,keyEncipherment"
pem banca-online.atlantida.example.pem banca-online.atlantida.example.pem
issue api-pagos.atlantida.example "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" "digitalSignature"
openssl x509 -in api-pagos.atlantida.example.pem -outform DER -out "$S/api-pagos.atlantida.example.der"
# Ejemplo deliberadamente defectuoso: firmado con SHA-1 y sin SubjectAltName.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out bad.key 2>/dev/null
openssl req -new -key bad.key -subj "$O/CN=intranet-legada.atlantida.example" -out bad.csr
printf 'basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > bad.ext
openssl x509 -req -in bad.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -sha1 -extfile bad.ext -out bad.pem 2>/dev/null
{ echo "$HDR"; echo "# Ejemplo DELIBERADAMENTE DEFECTUOSO: firma SHA-1 y sin SubjectAltName."; cat bad.pem; } > "$S/intranet-legada-defectuoso.pem"

# Piloto PQC: ML-DSA-65 autofirmado (FIPS 204)
openssl req -x509 -newkey ML-DSA-65 -nodes -keyout mldsa.key -out mldsa.pem -days 730 -subj "$O/CN=piloto-pqc.atlantida.example" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "subjectAltName=DNS:piloto-pqc.atlantida.example" 2>/dev/null
pem mldsa.pem piloto-pqc-mldsa65.pem
# SLH-DSA-SHA2-128s autofirmado (FIPS 205)
openssl req -x509 -newkey SLH-DSA-SHA2-128s -nodes -keyout slh.key -out slh.pem -days 730 -subj "$O/CN=firma-archivo.atlantida.example" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature,nonRepudiation" -addext "subjectAltName=DNS:firma-archivo.atlantida.example" 2>/dev/null
pem slh.pem firma-archivo-slhdsa.pem
# Clave pública ML-KEM-768 (FIPS 203) certificada por la clave ML-DSA-65 del piloto
openssl genpkey -algorithm ML-KEM-768 -out kem.key 2>/dev/null
openssl pkey -in kem.key -pubout -out kem.pub
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nsubjectAltName=DNS:kem-pagos.atlantida.example\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > kem.ext
openssl x509 -new -force_pubkey kem.pub -subj "$O/CN=kem-pagos.atlantida.example" -CA mldsa.pem -CAkey mldsa.key -days 397 -extfile kem.ext -out kem.pem 2>/dev/null
pem kem.pem kem-pagos-mlkem768.pem
# Certificado compuesto ML-DSA-65 + ECDSA P-256 (borrador IETF lamps): estructura de ejemplo, firma no verificable.
python3 "$ROOT/tools/gen-composite.py" > comp.pem
{ echo "$HDR"; echo "# Certificado COMPUESTO de ejemplo (OID provisional de draft-ietf-lamps-pq-composite-sigs). La firma es de relleno: sirve para probar el inventario, no para verificar."; cat comp.pem; } > "$S/composite-mldsa65-ecdsa-p256.pem"

# Salida s_client con el certificado de api-pagos regenerado
python3 - "$S" api-pagos.atlantida.example.pem <<'PY'
import sys, re, pathlib
s = pathlib.Path(sys.argv[1]) / "openssl-s_client-api-pagos.txt"
pemtxt = open(sys.argv[2]).read().strip()
t = s.read_text(encoding="utf-8")
t = re.sub(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", pemtxt, t)
s.write_text(t, encoding="utf-8")
PY
echo "Certificados regenerados en $S"
