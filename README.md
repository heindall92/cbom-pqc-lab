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
7. **Indicador de preparación PQC** (0-100), **sensibilidad de Mosca** por escenario de Z, **informe** en Markdown o imprimible a PDF, e **importación de un CBOM** CycloneDX para reeditarlo (desde v0.2).

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
npm install --no-save ajv@8 ajv-formats playwright
npm test                       # pruebas unitarias + validación con el esquema CycloneDX 1.6
python3 serve.py 8765 --no-browser &
npx playwright install chromium
npm run test:e2e               # navegador headless: escritorio y 390 px, claro y oscuro
```

- `tests/unit.mjs`: clasificación, analizadores con entradas malformadas (PEM basura, DER aleatorio, ficheros vacíos, `include`, comentarios, `Match`, selectores genéricos), extensiones X.509, indicador y Mosca. Incluye las regresiones de los fallos corregidos en v0.2.
- `tests/validate-cbom.mjs`: genera el CBOM de las muestras y lo valida con el esquema oficial CycloneDX 1.6 (`tests/schema/`). Admite ficheros extra: `node tests/validate-cbom.mjs cbom.json`.
- `tests/e2e.mjs`: todas las pestañas, soltar/elegir/pegar ficheros, casos límite de Mosca, alta y baja de activos, persistencia y `localStorage` corrupto, exportación, informe, teclado, ARIA, errores de consola y desbordamiento horizontal. Con `SHOTS=carpeta` guarda capturas.

## Estructura

```
index.html        interfaz
css/app.css       estilos
js/x509.js        lector DER/ASN.1 de certificados
js/parsers.js     nginx, sshd, openssl.cnf, s_client, nmap, openssl ciphers -v, CBOM JSON
js/classify.js    clasificación cuántica de algoritmos
js/mosca.js       Teorema de Mosca
js/plan.js        plan de transición
js/cbom.js        exportación CycloneDX 1.6
js/report.js      indicador de preparación, cadena X.509 e informe Markdown
samples/          datos de ejemplo ficticios
tools/            regeneración de js/samples.js
```

## Limitaciones conocidas (v0.2)

- Analiza texto y ficheros, no endpoints en vivo.
- No sigue `include` de nginx ni `Include` de sshd (avisa y pide cargar esos ficheros). No expande selectores genéricos de OpenSSL como `HIGH:!aNULL`: avisa y propone pegar la salida de `openssl ciphers -v`, que sí se analiza.
- La cadena de certificados se reconstruye por nombre e identificadores de clave entre los ficheros cargados; **no se verifican firmas** ni revocación. Los certificados compuestos PQC aún no se reconocen.
- El indicador de preparación PQC es una ponderación propia y visible de esta herramienta, no una métrica estándar.
- Al importar un CBOM se reclasifican sus algoritmos; certificados y protocolos no se reconstruyen.
- Los valores de X, Y y Z son ilustrativos; la prioridad del plan es orientativa y no constituye un dictamen de cumplimiento normativo.

## Cambios

### v0.2

Corregido:
- nginx y sshd: los comentarios al final de línea (`... # RC4`) se analizaban como configuración.
- nginx: valores entre comillas en `ssl_ecdh_curve`, grupos duplicados y aviso de TLS 1.0 en falso positivo.
- sshd: `-lista` (eliminar de los valores por defecto) se inventariaba como algoritmo habilitado; no se admitía la forma `Clave=valor`; los bloques `Match` se mezclaban con la configuración global.
- openssl.cnf: `DEFAULT@SECLEVEL=2` y otros selectores aparecían como algoritmos «sin clasificar».
- Certificados malformados o DER aleatorio mostraban errores internos de JavaScript; un certificado ilegible impedía leer el resto del fichero.
- Ficheros vacíos se marcaban como «formato no reconocido» sin explicación.
- Mosca: aceptaba años negativos y mostraba decimales en coma flotante (`0.30000000000000004`); el campo Z no se podía vaciar al escribir.
- `localStorage` corrupto o con forma inesperada bloqueaba la aplicación al cargar.
- Pestañas sin `aria-controls`/`tabpanel` ni navegación con flechas, Inicio y Fin.
- Clasificación: faltaban esquemas de firma TLS 1.3 (`rsa_pss_rsae_sha256`, `ecdsa_secp256r1_sha256`…), `sha256WithRSAEncryption`, `AES256`, `DES`, ECDSA secp256k1 y claves RSA/EC con parámetros no estándar.
- Fechas de validez partidas en móvil; contraste de rojo y verde en tema claro elevado a ≥ 7:1; animaciones de entrada acortadas.

Añadido:
- Extensiones X.509 (CA y pathLen, usos de clave, EKU, SAN, SKI/AKI), número de serie, estado de cadena entre los certificados cargados y avisos de caducidad, SHA-1, RSA < 2048 y ausencia de SAN.
- Avisos de `include`/`Include`, `Match`, listas `+`/`^` de OpenSSH y selectores genéricos de OpenSSL; análisis de la salida de `openssl ciphers -v`.
- Importación de un CBOM CycloneDX (JSON) para reeditarlo.
- Indicador de preparación PQC con su ponderación a la vista.
- Tabla de sensibilidad de Mosca por escenario de Z.
- Informe en Markdown e impresión a PDF.
- Pruebas unitarias y de extremo a extremo (Playwright).

### v0.1

Versión inicial: generador de CBOM, calculadora de Mosca, plan de transición PQC y exportación CycloneDX 1.6.

## Licencias de terceros

Lucide (ISC) y Inter (SIL OFL 1.1), incluidos en `vendor/`.
