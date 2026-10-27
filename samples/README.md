# Datos de ejemplo

Todos los ficheros de esta carpeta pertenecen a una entidad **ficticia** ("Banco Ficticio Atlántida S.A.") y a dominios `.example` reservados. Los certificados se generaron localmente solo para la demo con `tools/gen-certs.sh` (OpenSSL 3.5); las claves privadas no se incluyen.

- `intranet-legada-defectuoso.pem` es **deliberadamente defectuoso** (firma SHA-1, sin SubjectAltName) para mostrar los avisos.
- `piloto-pqc-mldsa65.pem` (ML-DSA-65), `firma-archivo-slhdsa.pem` (SLH-DSA-SHA2-128s) y `kem-pagos-mlkem768.pem` (clave pública ML-KEM-768) usan OID definitivos de NIST.
- `composite-mldsa65-ecdsa-p256.pem` es un certificado **compuesto de ejemplo** con el OID provisional `1.3.6.1.5.5.7.6.45` de draft-ietf-lamps-pq-composite-sigs-19. Su clave pública es real, pero la firma es de relleno y no se puede verificar.
