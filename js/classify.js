// Clasificación de algoritmos frente a la amenaza cuántica.
// Categorías: vulnerable (Shor), hybrid (clásico + PQC), pqc (FIPS 203/204/205),
// symmetric (aceptable con tamaño adecuado frente a Grover), legacy (débil ya hoy).

export const CATEGORIES = {
  vulnerable: { label: "Vulnerable cuántico", short: "Vulnerable", order: 0 },
  legacy: { label: "Obsoleto hoy", short: "Obsoleto", order: 1 },
  hybrid: { label: "Híbrido PQC", short: "Híbrido", order: 2 },
  pqc: { label: "Post-cuántico", short: "PQC", order: 3 },
  symmetric: { label: "Simétrico aceptable", short: "Simétrico OK", order: 4 },
  unknown: { label: "Sin clasificar", short: "Revisar", order: 5 },
};

export const ROLES = {
  kex: "Intercambio de claves",
  sig: "Firma / autenticación",
  pke: "Cifrado de clave pública",
  sym: "Cifrado simétrico",
  mac: "Hash / MAC",
};

// [regex, datos]. El primer patrón que coincide gana.
const RULES = [
  // Híbridos PQC
  [/^x25519mlkem768$/i, { name: "X25519MLKEM768", cat: "hybrid", role: "kex", primitive: "kem", param: "768", nistQ: 3, note: "Híbrido X25519 + ML-KEM-768 (FIPS 203). Protege frente a HNDL." }],
  [/^secp256r1mlkem768$/i, { name: "SecP256r1MLKEM768", cat: "hybrid", role: "kex", primitive: "kem", param: "768", nistQ: 3, note: "Híbrido P-256 + ML-KEM-768." }],
  [/^secp384r1mlkem1024$/i, { name: "SecP384r1MLKEM1024", cat: "hybrid", role: "kex", primitive: "kem", param: "1024", nistQ: 5, note: "Híbrido P-384 + ML-KEM-1024." }],
  [/^x25519kyber768(draft00)?$/i, { name: "X25519Kyber768Draft00", cat: "hybrid", role: "kex", primitive: "kem", param: "768", nistQ: 3, note: "Borrador previo a FIPS 203. Sustituir por X25519MLKEM768." }],
  [/^mlkem768x25519-sha256$/i, { name: "mlkem768x25519-sha256", cat: "hybrid", role: "kex", primitive: "kem", param: "768", nistQ: 3, note: "KEX híbrido SSH (OpenSSH 9.9+)." }],
  [/^sntrup761x25519-sha512(@openssh\.com)?$/i, { name: "sntrup761x25519-sha512", cat: "hybrid", role: "kex", primitive: "kem", param: "761", note: "Híbrido SSH con NTRU Prime (no estandarizado por NIST)." }],
  // PQC puros
  [/^(ml-?kem-?|mlkem)(512|768|1024)$/i, { name: (m) => `ML-KEM-${m[2]}`, cat: "pqc", role: "kex", primitive: "kem", param: (m) => m[2], nistQ: (m) => ({ 512: 1, 768: 3, 1024: 5 })[m[2]], note: "FIPS 203." }],
  [/^(ml-?dsa-?|mldsa)(44|65|87)$/i, { name: (m) => `ML-DSA-${m[2]}`, cat: "pqc", role: "sig", primitive: "signature", param: (m) => m[2], nistQ: (m) => ({ 44: 2, 65: 3, 87: 5 })[m[2]], note: "FIPS 204." }],
  [/^slh-?dsa/i, { name: "SLH-DSA", cat: "pqc", role: "sig", primitive: "signature", nistQ: 1, note: "FIPS 205 (hash-based)." }],
  // Intercambio de claves clásico
  [/^diffie-hellman-group1-sha1$|^diffie-hellman-group-exchange-sha1$/i, { name: (m) => m[0], cat: "legacy", role: "kex", primitive: "key-agree", note: "DH con SHA-1: débil ya hoy." }],
  [/^diffie-hellman-group(14|16|18)-sha(256|512)$/i, { name: (m) => m[0], cat: "vulnerable", role: "kex", primitive: "key-agree", note: "DH finito: roto por Shor." }],
  [/^diffie-hellman-group14-sha1$/i, { name: "diffie-hellman-group14-sha1", cat: "legacy", role: "kex", primitive: "key-agree", note: "SHA-1 en KEX." }],
  [/^curve25519-sha256(@libssh\.org)?$/i, { name: "curve25519-sha256", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "Curve25519", note: "ECDH X25519: roto por Shor (HNDL)." }],
  [/^ecdh-sha2-nistp(256|384|521)$/i, { name: (m) => m[0], cat: "vulnerable", role: "kex", primitive: "key-agree", curve: (m) => `P-${m[1]}`, note: "ECDH NIST: roto por Shor (HNDL)." }],
  [/^x25519$/i, { name: "X25519", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "Curve25519", classical: 128, note: "ECDH clásico: tráfico grabado hoy descifrable con un CRQC (HNDL)." }],
  [/^x448$/i, { name: "X448", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "Curve448", classical: 224, note: "ECDH clásico." }],
  [/^(secp256r1|prime256v1|p-256)$/i, { name: "ECDH P-256", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "P-256", classical: 128, note: "ECDH clásico (HNDL)." }],
  [/^(secp384r1|p-384)$/i, { name: "ECDH P-384", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "P-384", classical: 192, note: "ECDH clásico (HNDL)." }],
  [/^(secp521r1|p-521)$/i, { name: "ECDH P-521", cat: "vulnerable", role: "kex", primitive: "key-agree", curve: "P-521", classical: 256, note: "ECDH clásico (HNDL)." }],
  [/^ffdhe(2048|3072|4096|6144|8192)$/i, { name: (m) => `FFDHE-${m[1]}`, cat: "vulnerable", role: "kex", primitive: "key-agree", param: (m) => m[1], note: "DH finito (HNDL)." }],
  [/^(ecdhe|eecdh)$/i, { name: "ECDHE", cat: "vulnerable", role: "kex", primitive: "key-agree", note: "ECDHE clásico; el grupo concreto depende de la configuración (HNDL)." }],
  [/^(dhe|edh)$/i, { name: "DHE", cat: "vulnerable", role: "kex", primitive: "key-agree", note: "DH efímero clásico (HNDL)." }],
  [/^rsa-kex$/i, { name: "RSA (transporte de clave)", cat: "vulnerable", role: "pke", primitive: "pke", padding: "pkcs1v15", note: "Sin secreto perfecto hacia adelante: una sola clave descifra todo el tráfico grabado." }],
  // Firmas / claves públicas
  [/^rsa-(\d{3,5})$/i, { name: (m) => `RSA-${m[1]}`, cat: (m) => (+m[1] < 2048 ? "legacy" : "vulnerable"), role: "sig", primitive: "signature", param: (m) => m[1], classical: (m) => ({ 1024: 80, 2048: 112, 3072: 128, 4096: 152 })[m[1]], note: "Clave RSA: rota por Shor." }],
  [/^ecdsa-secp256k1$/i, { name: "ECDSA secp256k1", cat: "vulnerable", role: "sig", primitive: "signature", curve: "secp256k1", classical: 128, note: "Clave ECDSA: rota por Shor." }],
  [/^ecdsa_(secp256r1_sha256|secp384r1_sha384|secp521r1_sha512)$/i, { name: (m) => m[0].toLowerCase(), cat: "vulnerable", role: "sig", primitive: "signature", note: "Esquema de firma TLS 1.3 ECDSA." }],
  [/^rsa_pss_(rsae|pss)_sha(256|384|512)$/i, { name: (m) => m[0].toLowerCase(), cat: "vulnerable", role: "sig", primitive: "signature", padding: "other", note: "Esquema de firma TLS 1.3 RSA-PSS." }],
  [/^rsa_pkcs1_sha1$|^ecdsa_sha1$/i, { name: (m) => m[0].toLowerCase(), cat: "legacy", role: "sig", primitive: "signature", note: "Firma TLS con SHA-1: débil ya hoy." }],
  [/^rsa_pkcs1_sha(256|384|512)$/i, { name: (m) => m[0].toLowerCase(), cat: "vulnerable", role: "sig", primitive: "signature", note: "Esquema de firma TLS RSA PKCS#1 v1.5." }],
  [/^(sha1withrsaencryption)$/i, { name: "SHA1withRSA", cat: "legacy", role: "sig", primitive: "signature", note: "Firma con SHA-1: débil ya hoy." }],
  [/^sha(256|384|512)withrsaencryption$/i, { name: (m) => `SHA${m[1]}withRSA`, cat: "vulnerable", role: "sig", primitive: "signature", note: "Firma RSA PKCS#1 v1.5." }],
  [/^ecdsa-(p-\d{3})$/i, { name: (m) => `ECDSA ${m[1].toUpperCase()}`, cat: "vulnerable", role: "sig", primitive: "signature", curve: (m) => m[1].toUpperCase(), classical: (m) => ({ "P-256": 128, "P-384": 192, "P-521": 256 })[m[1].toUpperCase()], note: "Clave ECDSA: rota por Shor." }],
  [/^(sha1withrsa|md5withrsa|ssh-rsa|ssh-dss|dsa)$/i, { name: (m) => m[0], cat: "legacy", role: "sig", primitive: "signature", note: "Firma con SHA-1/MD5 o DSA: débil ya hoy." }],
  [/^sha(256|384|512)withrsa$/i, { name: (m) => `SHA${m[1]}withRSA`, cat: "vulnerable", role: "sig", primitive: "signature", note: "Firma RSA PKCS#1 v1.5." }],
  [/^sha(256|384|512)withecdsa$/i, { name: (m) => `SHA${m[1]}withECDSA`, cat: "vulnerable", role: "sig", primitive: "signature", note: "Firma ECDSA." }],
  [/^(rsassa-pss|rsa-pss)$/i, { name: "RSASSA-PSS", cat: "vulnerable", role: "sig", primitive: "signature", padding: "other", note: "Firma RSA-PSS." }],
  [/^rsa-sha2-(256|512)$/i, { name: (m) => m[0], cat: "vulnerable", role: "sig", primitive: "signature", note: "Clave de host / firma RSA en SSH." }],
  [/^ecdsa-sha2-nistp(256|384|521)$/i, { name: (m) => m[0], cat: "vulnerable", role: "sig", primitive: "signature", curve: (m) => `P-${m[1]}`, note: "Clave de host ECDSA." }],
  [/^(ssh-ed25519|ed25519)$/i, { name: (m) => (m[0].toLowerCase() === "ed25519" ? "Ed25519" : "ssh-ed25519"), cat: "vulnerable", role: "sig", primitive: "signature", curve: "Ed25519", classical: 128, note: "EdDSA: rota por Shor." }],
  [/^ed448$/i, { name: "Ed448", cat: "vulnerable", role: "sig", primitive: "signature", curve: "Ed448", note: "EdDSA." }],
  [/^rsa$/i, { name: "RSA", cat: "vulnerable", role: "sig", primitive: "signature", note: "Autenticación RSA." }],
  [/^ecdsa$/i, { name: "ECDSA", cat: "vulnerable", role: "sig", primitive: "signature", note: "Autenticación ECDSA." }],
  // Simétricos
  [/^(aes-?256-?gcm|aes256-gcm(@openssh\.com)?)$/i, { name: "AES-256-GCM", cat: "symmetric", role: "sym", primitive: "ae", mode: "gcm", param: "256", classical: 256, nistQ: 5, note: "Robusto frente a Grover." }],
  [/^(aes-?128-?gcm|aes128-gcm(@openssh\.com)?)$/i, { name: "AES-128-GCM", cat: "symmetric", role: "sym", primitive: "ae", mode: "gcm", param: "128", classical: 128, nistQ: 1, note: "Aceptable; para datos de vida larga preferir AES-256." }],
  [/^aes-?(128|256)-?ccm$/i, { name: (m) => `AES-${m[1]}-CCM`, cat: "symmetric", role: "sym", primitive: "ae", mode: "ccm", param: (m) => m[1], note: "AEAD." }],
  [/^aes-?gcm$/i, { name: "AES-GCM", cat: "symmetric", role: "sym", primitive: "ae", mode: "gcm", note: "Tamaño de clave según la suite negociada." }],
  [/^(aes(128|192|256)-ctr)$/i, { name: (m) => `AES-${m[2]}-CTR`, cat: "symmetric", role: "sym", primitive: "block-cipher", mode: "ctr", param: (m) => m[2], note: "Requiere MAC separado (EtM)." }],
  [/^aes-?(128|256)-?cbc$/i, { name: (m) => `AES-${m[1]}-CBC`, cat: "symmetric", role: "sym", primitive: "block-cipher", mode: "cbc", param: (m) => m[1], note: "Seguro frente a cuántica, pero CBC en TLS tiene historial de ataques de padding: preferir AEAD." }],
  [/^(chacha20-poly1305(@openssh\.com)?|chacha20)$/i, { name: "ChaCha20-Poly1305", cat: "symmetric", role: "sym", primitive: "ae", param: "256", classical: 256, note: "AEAD de 256 bits." }],
  [/^aes-?(128|256)$/i, { name: (m) => `AES-${m[1]}`, cat: "symmetric", role: "sym", primitive: "block-cipher", param: (m) => m[1], note: "Modo no indicado en la fuente." }],
  [/^camellia-?(128|256)(-gcm|-cbc)?$/i, { name: (m) => `Camellia-${m[1]}`, cat: "symmetric", role: "sym", primitive: "block-cipher", param: (m) => m[1], note: "Cifrado por bloques de 128 bits; poco soporte actual." }],
  [/^des(-cbc)?$/i, { name: "DES", cat: "legacy", role: "sym", primitive: "block-cipher", mode: "cbc", param: "56", note: "Clave de 56 bits: roto. Retirar ya." }],
  [/^(3des|des-cbc3|3des-ede-cbc|3des-cbc)$/i, { name: "3DES-EDE-CBC", cat: "legacy", role: "sym", primitive: "block-cipher", mode: "cbc", param: "112", note: "Bloque de 64 bits (Sweet32). Retirar ya." }],
  [/^rc4(-128)?$/i, { name: "RC4", cat: "legacy", role: "sym", primitive: "stream-cipher", note: "Roto. Retirar ya." }],
  // Hash / MAC
  [/^(sha-?(256|384|512))$/i, { name: (m) => `SHA-${m[2]}`, cat: "symmetric", role: "mac", primitive: "hash", param: (m) => m[2], note: "Hash/PRF." }],
  [/^(sha-?1|sha)$/i, { name: "SHA-1", cat: "legacy", role: "mac", primitive: "hash", note: "Colisiones prácticas." }],
  [/^md5$/i, { name: "MD5", cat: "legacy", role: "mac", primitive: "hash", note: "Roto." }],
  [/^poly1305$/i, { name: "Poly1305", cat: "symmetric", role: "mac", primitive: "mac", note: "MAC de ChaCha20-Poly1305." }],
  [/^hmac-sha2-(256|512)(-etm@openssh\.com)?$/i, { name: (m) => m[0], cat: "symmetric", role: "mac", primitive: "mac", note: "HMAC-SHA2." }],
  [/^(hmac-sha1|hmac-md5)(-etm@openssh\.com|-96)?$/i, { name: (m) => m[0], cat: "legacy", role: "mac", primitive: "mac", note: "HMAC con hash obsoleto." }],
  [/^umac-(64|128)(-etm)?@openssh\.com$/i, { name: (m) => m[0], cat: "symmetric", role: "mac", primitive: "mac", note: "UMAC." }],
];

export function classify(raw) {
  const s = String(raw).trim();
  for (const [re, d] of RULES) {
    const m = s.match(re);
    if (!m) continue;
    const v = (x) => (typeof x === "function" ? x(m) : x);
    return {
      name: v(d.name), category: v(d.cat), role: d.role, primitive: d.primitive,
      paramSet: v(d.param) || null, curve: v(d.curve) || null, mode: d.mode || null,
      padding: d.padding || null, classical: v(d.classical) ?? null, nistQ: v(d.nistQ) ?? null, note: d.note,
    };
  }
  return { name: s, category: "unknown", role: null, primitive: "unknown", note: "Algoritmo no reconocido: revisar manualmente." };
}

// Descompone una suite TLS (nombre IANA u OpenSSL) en algoritmos primitivos.
export function decomposeSuite(suite) {
  const s = suite.trim().toUpperCase();
  const out = [];
  if (s.startsWith("TLS_")) {
    if (!s.includes("_WITH_")) {
      const body = s.slice(4);
      const mac = body.match(/_(SHA\d+)$/);
      out.push(body.replace(/_(SHA\d+)$/, "").replace(/_/g, "-"));
      if (mac) out.push(mac[1]);
      return { version: "1.3", algs: out.map(fixSym) };
    }
    const [kx, rest] = s.slice(4).split("_WITH_");
    const k = kx.split("_");
    if (k[0] === "RSA") out.push("RSA-KEX");
    else { out.push(k[0]); if (k[1]) out.push(k[1]); }
    const mac = rest.match(/_(SHA\d*|MD5)$/);
    let ciph = rest.replace(/_(SHA\d*|MD5)$/, "");
    if (/POLY1305$/.test(ciph)) ciph = "CHACHA20-POLY1305";
    else if (/3DES/.test(ciph)) ciph = "3DES";
    else if (/^RC4/.test(ciph)) ciph = "RC4";
    else ciph = ciph.replace(/_/g, "-");
    out.push(ciph);
    if (mac && !/GCM|CCM|POLY/.test(rest)) out.push(mac[1]);
    else if (mac) out.push(mac[1]);
    return { version: "1.2", algs: out.map(fixSym) };
  }
  // Nombre OpenSSL
  const t = s.split("-");
  let i = 0;
  if (t[i] === "ECDHE" || t[i] === "DHE" || t[i] === "EDH") { out.push(t[i]); i++; if (t[i] === "RSA" || t[i] === "ECDSA") { out.push(t[i]); i++; } }
  else { out.push("RSA-KEX"); }
  const rest = t.slice(i).join("-");
  let mac = null;
  let ciph = rest;
  const mm = rest.match(/-(SHA\d*|MD5)$/);
  if (mm) { mac = mm[1]; ciph = rest.slice(0, -mm[0].length); }
  if (/CHACHA20/.test(ciph)) ciph = "CHACHA20-POLY1305";
  else if (/DES-CBC3|3DES/.test(ciph)) ciph = "3DES";
  else if (/^RC4/.test(ciph)) ciph = "RC4";
  else if (/^AES(128|256)-(GCM|CCM)$/.test(ciph)) ciph = ciph.replace(/^AES(\d+)/, "AES-$1");
  else if (/^AES(128|256)$/.test(ciph)) ciph = ciph.replace(/^AES(\d+)/, "AES-$1-CBC");
  out.push(ciph);
  if (mac) out.push(mac);
  return { version: "1.2", algs: out.map(fixSym) };
}

function fixSym(a) {
  return a.replace(/^AES-(128|256)-CBC$/, "AES-$1-CBC").replace(/^SHA$/, "SHA-1");
}
