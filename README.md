# CBOM & PQC Lab para Banca

> Nombre provisional. Versión 0.1.

Herramienta local, en el navegador, para inventariar la criptografía de una entidad financiera, medir su exposición post-cuántica con el Teorema de Mosca y generar un plan de transición hacia los estándares NIST PQC, exportable como **CBOM CycloneDX 1.6**.

## El problema

- **Harvest Now, Decrypt Later (HNDL).** Un atacante puede capturar hoy tráfico o copias de seguridad cifradas con RSA o curvas elípticas y guardarlas hasta que exista un ordenador cuántico capaz de romperlas. El intercambio de claves que se negocia hoy decide si esos datos estarán expuestos mañana.
- **En banca, los datos viven mucho.** Un expediente hipotecario, un historial crediticio o la evidencia de una firma transaccional deben seguir siendo confidenciales o íntegros durante 10 a 30 años. Migrar una infraestructura bancaria (HSM, PKI, canales, proveedores) también lleva años.
- **DORA.** El Reglamento (UE) 2022/2554 exige un marco de gestión del riesgo TIC. Su desarrollo técnico, el Reglamento Delegado (UE) 2024/1774, pide en su artículo 6 una política de cifrado y controles criptográficos basada en la clasificación de los datos, con previsiones para actualizar la criptografía según la evolución del criptoanálisis, y en su artículo 7 la gestión del ciclo de vida de las claves; su considerando 9 menciona las amenazas de los avances cuánticos. Sin un inventario criptográfico no hay forma de demostrar nada de eso.

## Qué hace

1. **Generador de CBOM.** Suelta o pega certificados X.509 (PEM o DER), `nginx.conf`, `sshd_config`, políticas TLS tipo `openssl.cnf`, o la salida de `openssl s_client` y `nmap --script ssl-enum-ciphers`. El análisis ASN.1/DER se hace en el navegador y extrae tipo y tamaño de clave (RSA-2048, ECDSA P-256, ML-DSA-65…), algoritmo de firma, validez, grupos de intercambio (clásicos frente a híbridos como `X25519MLKEM768`), suites TLS y `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` y `MACs` de SSH. Cada algoritmo se clasifica como *vulnerable cuántico*, *obsoleto hoy*, *híbrido PQC*, *post-cuántico* o *simétrico aceptable*.
2. **Calculadora del Teorema de Mosca.** Activos bancarios predefinidos (expediente hipotecario, historial crediticio, firma transaccional, token de sesión, log transaccional) con X (años de confidencialidad), Y (años de migración) y Z (horizonte de amenaza cuántica). Si **X + Y > Z**, el activo queda marcado con *deuda criptográfica crítica*, con una línea temporal visual. Z se presenta como supuesto editable (escenarios pesimista, central y optimista), no como predicción. Cada activo se vincula a los protocolos y certificados por los que viaja.
3. **Plan de transición NIST PQC + DORA.** Cada elemento vulnerable u obsoleto se asigna a su destino: FIPS 203 (ML-KEM) para intercambio de claves, FIPS 204 (ML-DSA) para firmas y FIPS 205 (SLH-DSA) para raíces de larga vida, con prioridad P1/P2/P3 derivada del resultado de Mosca y un estado de seguimiento.
4. **Exportación CycloneDX 1.6.** Componentes `cryptographic-asset` con `cryptoProperties` (algoritmos, certificados, claves públicas y protocolos), dependencias entre ellos, y clasificación y prioridad como propiedades. La estructura se valida contra el esquema oficial (ver *Pruebas*).
5. **Datos de ejemplo** de una entidad ficticia ("Banco Ficticio Atlántida S.A.", dominios `.example`) en `samples/`, cargables con un clic.
6. Estado guardado solo en `localStorage`, con opción de restablecer todo. Tema claro y oscuro.

## Cómo ejecutarlo

Necesitas Python 3 (sin dependencias). No hay paso de compilación.

**Windows:** doble clic en `Iniciar.bat`. Se abrirá `http://127.0.0.1:8765/` en tu navegador. Si no tienes Python, instálalo desde python.org marcando *Add python.exe to PATH*.

**macOS / Linux:**

```sh
./serve.sh            # o: python3 serve.py
python3 serve.py 9000 # otro puerto
```

El servidor solo escucha en `127.0.0.1`. Funciona sin conexión a internet: la tipografía (Inter) y los iconos (Lucide) van incluidos en `vendor/`.

### Analizar un servidor real

Un navegador no puede abrir conexiones TLS ni escanear puertos. Ejecuta la herramienta en tu equipo y pega la salida en *Pegar texto*:

```sh
openssl s_client -connect host:443 -groups X25519MLKEM768:X25519 </dev/null
nmap --script ssl-enum-ciphers -p 443 host
```

## Privacidad

- Todo el análisis ocurre en el navegador. No hay backend, ni subidas, ni telemetría, ni recursos externos.
- La página declara una Content-Security-Policy con `connect-src 'none'`, de modo que el código no puede enviar datos a la red.
- Lo que cargas se guarda solo en el `localStorage` de tu navegador. *Exportar → Restablecer todo* lo borra.
- No cargues claves privadas: la herramienta no las necesita.

## Pruebas

```sh
npm install
npm test
```

`tests/validate-cbom.mjs` analiza las muestras, genera el CBOM y lo valida con el esquema oficial CycloneDX 1.6 (`tests/schema/`), además de comprobar la lógica de Mosca.

## Estructura

```
index.html        interfaz
css/app.css       estilos
js/x509.js        lector DER/ASN.1 de certificados
js/parsers.js     nginx, sshd, openssl.cnf, s_client, nmap
js/classify.js    clasificación cuántica de algoritmos
js/mosca.js       Teorema de Mosca
js/plan.js        plan de transición
js/cbom.js        exportación CycloneDX 1.6
samples/          datos de ejemplo ficticios
tools/            regeneración de js/samples.js
```

## Limitaciones conocidas (v0.1)

- Analiza texto y ficheros, no endpoints en vivo.
- No interpreta `include` de nginx ni cadenas de cifrado OpenSSL abstractas como `HIGH:!aNULL` (se ignoran los selectores genéricos).
- La clasificación de extensiones X.509, cadenas de confianza y certificados compuestos PQC aún no está implementada.
- Los valores de X, Y y Z son ilustrativos; la prioridad del plan es orientativa y no constituye un dictamen de cumplimiento normativo.

## Licencias de terceros

Lucide (ISC) y Inter (SIL OFL 1.1), incluidos en `vendor/`.
