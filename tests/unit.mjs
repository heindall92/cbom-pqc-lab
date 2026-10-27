// Pruebas unitarias y de regresión de analizadores, clasificación y Mosca. Uso: node tests/unit.mjs
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const { parseSource, strip } = await import("../js/parsers.js");
const { classify, decomposeSuite } = await import("../js/classify.js");
const { buildInventory } = await import("../js/inventory.js");
const { evaluate, sensitivity } = await import("../js/mosca.js");
const { readiness, chainStatus } = await import("../js/report.js");
const { SAMPLES } = await import("../js/samples.js");

let ok = 0; const bad = [];
const t = (cond, msg) => (cond ? ok++ : bad.push(msg));
const P = (name, text, bytes) => parseSource({ name, text, bytes });
const raws = (r) => r.algs.map((a) => a.raw);
const warns = (r) => r.warnings.join(" | ");

// Clasificación
const cat = (a) => classify(a).category;
for (const a of ["RSA-2048", "RSA-4096", "ECDSA-P-256", "X25519", "ECDHE", "ssh-ed25519", "ECDSA-secp256k1", "rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256", "sha256WithRSAEncryption"]) t(cat(a) === "vulnerable", `${a} vulnerable`);
for (const a of ["X25519MLKEM768", "SecP256r1MLKEM768", "mlkem768x25519-sha256"]) t(cat(a) === "hybrid", `${a} híbrido`);
for (const a of ["ML-KEM-768", "MLKEM1024", "ML-DSA-65", "mldsa87", "SLH-DSA"]) t(cat(a) === "pqc", `${a} PQC`);
for (const a of ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "AES256", "SHA-384"]) t(cat(a) === "symmetric", `${a} simétrico`);
for (const a of ["3DES", "DES-CBC3", "RC4", "SHA1", "MD5", "RSA-1024", "sha1WithRSAEncryption", "DES", "rsa_pkcs1_sha1"]) t(cat(a) === "legacy", `${a} obsoleto`);
t(decomposeSuite("ECDHE-RSA-AES128-SHA").algs.join() === "ECDHE,RSA,AES-128-CBC,SHA-1", "suite OpenSSL con SHA1");
t(decomposeSuite("TLS_RSA_WITH_RC4_128_SHA").algs.includes("RC4"), "suite IANA RC4");

// Vacíos y binarios
t(/vacío/.test(warns(P("v.pem", ""))), "fichero vacío");
t(/vacío/.test(warns(P("v.der", undefined, new Uint8Array()))), "DER vacío");
for (const b of [[0x30, 0x03, 0x02, 0x01, 0x01], [0x30, 0x82, 0xff, 0xff, 1], [0x04, 0x01, 0x00], [0xff, 0xff, 0xff]]) {
  const w = warns(P("x.der", undefined, new Uint8Array(b)));
  t(/ilegible/.test(w) && !/undefined|properties/.test(w), `DER aleatorio legible: ${w}`);
}
t(/ilegible/.test(warns(P("g.pem", "-----BEGIN CERTIFICATE-----\nMIIB!!!@@\n-----END CERTIFICATE-----"))), "PEM basura");

// nginx
const ng = P("nginx.conf", `include /etc/nginx/conf.d/*.conf;
server { ssl_protocols TLSv1.2 TLSv1.3; # ssl_ciphers RC4-SHA;
  ssl_ciphers 'HIGH:!aNULL:!MD5:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_ecdh_curve "X25519MLKEM768:x25519";
  ssl_ecdh_curve X25519:prime256v1;
  ssl_conf_command Groups X25519MLKEM768;
}`);
t(!raws(ng).includes("RC4"), "nginx: comentario al final de línea ignorado");
t(raws(ng).includes("X25519MLKEM768") && !raws(ng).some((r) => r.includes('"')), "nginx: comillas en ssl_ecdh_curve");
t(raws(ng).filter((r) => r.toLowerCase() === "x25519").length === 1, "nginx: grupos deduplicados");
t(/include/i.test(warns(ng)), "nginx: aviso include");
t(/HIGH/.test(warns(ng)) && !raws(ng).includes("HIGH"), "nginx: selectores genéricos avisados, no inventariados");
t(!/1\.0\/1\.1/.test(warns(ng)), "nginx: sin falso aviso TLS 1.0");
t(/1\.0\/1\.1/.test(warns(P("n.conf", "ssl_protocols TLSv1 TLSv1.2;"))), "nginx: TLSv1 avisado");

// sshd
const sd = P("sshd_config", `KexAlgorithms mlkem768x25519-sha256,curve25519-sha256 # preferido
Ciphers=aes256-gcm@openssh.com
MACs -hmac-sha1
HostKeyAlgorithms +ssh-rsa
Include /etc/ssh/sshd_config.d/*.conf
Match User copias
  Ciphers aes128-ctr`);
t(sd.type === "sshd", "sshd detectado");
t(raws(sd).includes("curve25519-sha256") && !raws(sd).some((r) => r.includes("#")), "sshd: comentario final ignorado");
t(raws(sd).includes("aes256-gcm@openssh.com"), "sshd: sintaxis Clave=valor");
t(!raws(sd).includes("hmac-sha1"), "sshd: '-' elimina, no habilita");
t(/Include/.test(warns(sd)) && /Match/.test(warns(sd)) && /por defecto/.test(warns(sd)), "sshd: avisos Include/Match/+");
t(sd.algs.find((a) => a.raw === "aes128-ctr").ctx.includes("Match User copias"), "sshd: contexto Match");

// Política OpenSSL
const pol = P("p.cnf", "[s]\nCipherString = DEFAULT@SECLEVEL=2:ECDHE-ECDSA-AES256-GCM-SHA384\nGroups = X25519MLKEM768:X25519\nSignatureAlgorithms = ECDSA+SHA256:rsa_pss_rsae_sha256\nMinProtocol = TLSv1.2");
t(!raws(pol).some((r) => /DEFAULT|SECLEVEL/.test(r)), "política: @SECLEVEL no es algoritmo");
t(raws(pol).includes("rsa_pss_rsae_sha256") && cat("rsa_pss_rsae_sha256") === "vulnerable", "política: SignatureAlgorithms TLS 1.3");

// openssl ciphers -v
const cv = P("ciphers.txt", "ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(256)            Mac=AEAD\nDES-CBC3-SHA                   SSLv3   Kx=RSA      Au=RSA   Enc=3DES(168)              Mac=SHA1\n");
t(cv.type === "ciphers" && raws(cv).includes("3DES"), "openssl ciphers -v");

// CBOM importado
const bom = { bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "cryptographic-asset", name: "RSA-2048", cryptoProperties: { assetType: "algorithm" } }, { type: "cryptographic-asset", name: "X25519MLKEM768", cryptoProperties: { assetType: "algorithm" } }, { type: "library", name: "otro" }] };
const ib = P("cbom.json", JSON.stringify(bom));
t(ib.type === "cbom" && raws(ib).length === 2, "importar CBOM");
t(/ilegible|formato|Error/.test(warns(P("cbom.json", '{"bomFormat":"CycloneDX", "components": 5}'))), "CBOM inválido");

// Muestras: certificados, extensiones y cadena
const src = SAMPLES.map((s) => ({ name: s.name, parsed: parseSource(s.binary ? { name: s.name, bytes: Uint8Array.from(Buffer.from(s.b64, "base64")) } : { name: s.name, text: s.text }) }));
const inv = buildInventory(src);
t(inv.certificates.length >= 3 && inv.certificates.every((c) => c.serial && c.ext), "certificados con número de serie y extensiones");
t(inv.certificates.some((c) => c.ext.ca === true), "detecta CA (basicConstraints)");
const ch = chainStatus(inv.certificates);
t(Object.keys(ch).length === inv.certificates.length, "estado de cadena por certificado");
const r = readiness(inv);
t(r.score >= 0 && r.score <= 100 && r.parts.length >= 3, "indicador de preparación 0-100");
t(readiness({ algorithms: [], certificates: [], protocols: [] }).score === null, "indicador vacío sin datos");

// Mosca
for (const [x, y, z, exp] of [[30, 6, 10, true], [5, 5, 10, false], [0, 0, 0, false], [-5, -3, 10, false], [1e9, 1, 10, true]]) t(evaluate(x, y, z).critical === exp, `Mosca ${x},${y},${z}`);
t(evaluate(0.1, 0.2, 10).sum === 0.3, "Mosca redondea decimales");
t(evaluate(-5, 3, 10).X === 0, "Mosca sin negativos");
t(evaluate("", "", "").margin === 0 && evaluate("abc", 1, 1).X === 0, "Mosca entradas vacías o no numéricas");
t(sensitivity(30, 6).threshold === 36 && sensitivity(30, 6).byPreset.every((p) => p.ev.critical), "sensibilidad de Mosca");

// strip
t(strip('a "b#c" # d') === 'a "b#c" ', "strip respeta comillas");

console.log(`${ok} pruebas unitarias superadas, ${bad.length} fallos.`);
bad.forEach((b) => console.error("FALLO:", b));
process.exit(bad.length ? 1 : 0);
