// Lector DER/ASN.1 mínimo para certificados X.509. Solo lectura, sin dependencias.

function readTLV(buf, pos) {
  if (pos + 2 > buf.length) throw new Error("Estructura ASN.1 truncada");
  const tag = buf[pos];
  let len = buf[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error("Longitud ASN.1 no soportada");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr += n;
  }
  const start = pos + hdr;
  if (start + len > buf.length) throw new Error("Estructura ASN.1 truncada");
  return { tag, start, end: start + len, len, next: start + len };
}

function children(buf, node) {
  const out = [];
  let p = node.start;
  while (p < node.end) {
    const c = readTLV(buf, p);
    out.push(c);
    p = c.next;
  }
  return out;
}

function oid(buf, node) {
  const b = buf.subarray(node.start, node.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

function str(buf, node) {
  if (node.tag === 0x1e) return new TextDecoder("utf-16be").decode(buf.subarray(node.start, node.end));
  return new TextDecoder().decode(buf.subarray(node.start, node.end));
}

function time(buf, node) {
  const s = str(buf, node);
  let y, rest;
  if (node.tag === 0x17) { y = parseInt(s.slice(0, 2), 10); y += y < 50 ? 2000 : 1900; rest = s.slice(2); }
  else { y = parseInt(s.slice(0, 4), 10); rest = s.slice(4); }
  const [mo, d, h, mi, se] = [0, 2, 4, 6, 8].map((i) => parseInt(rest.slice(i, i + 2), 10) || 0);
  return new Date(Date.UTC(y, mo - 1, d, h, mi, se));
}

const NAME_OIDS = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.7": "L", "2.5.4.8": "ST" };

function name(buf, node) {
  const parts = [];
  for (const set of children(buf, node)) {
    for (const atv of children(buf, set)) {
      const [t, v] = children(buf, atv);
      parts.push(`${NAME_OIDS[oid(buf, t)] || oid(buf, t)}=${str(buf, v)}`);
    }
  }
  return parts.join(", ");
}

export const OIDS = {
  "1.2.840.113549.1.1.1": { name: "RSA", family: "RSA" },
  "1.2.840.113549.1.1.10": { name: "RSASSA-PSS", family: "RSA" },
  "1.2.840.10045.2.1": { name: "EC", family: "EC" },
  "1.3.101.112": { name: "Ed25519", family: "EdDSA" },
  "1.3.101.113": { name: "Ed448", family: "EdDSA" },
  "1.3.101.110": { name: "X25519", family: "ECDH" },
  "1.2.840.10040.4.1": { name: "DSA", family: "DSA" },
  "1.2.840.113549.1.1.5": { name: "SHA1withRSA", family: "RSA" },
  "1.2.840.113549.1.1.11": { name: "SHA256withRSA", family: "RSA" },
  "1.2.840.113549.1.1.12": { name: "SHA384withRSA", family: "RSA" },
  "1.2.840.113549.1.1.13": { name: "SHA512withRSA", family: "RSA" },
  "1.2.840.113549.1.1.4": { name: "MD5withRSA", family: "RSA" },
  "1.2.840.10045.4.3.2": { name: "SHA256withECDSA", family: "ECDSA" },
  "1.2.840.10045.4.3.3": { name: "SHA384withECDSA", family: "ECDSA" },
  "1.2.840.10045.4.3.4": { name: "SHA512withECDSA", family: "ECDSA" },
};

// PQC estandarizado. Fuente: NIST CSOR, "Computer Security Objects Register - Algorithm Registration"
// (sigAlgs = 2.16.840.1.101.3.4.3, kems = 2.16.840.1.101.3.4.4); RFC 9881 (ML-DSA en X.509).
const SIG = "2.16.840.1.101.3.4.3.";
[44, 65, 87].forEach((n, i) => {
  OIDS[`${SIG}${17 + i}`] = { name: `ML-DSA-${n}`, family: "ML-DSA", param: String(n) };
  OIDS[`${SIG}${32 + i}`] = { name: `HashML-DSA-${n}-SHA512`, family: "ML-DSA", param: String(n) };
});
const SLH = ["SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f", "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"];
const SLH_PH = ["SHA256", "SHA256", "SHA512", "SHA512", "SHA512", "SHA512", "SHAKE128", "SHAKE128", "SHAKE256", "SHAKE256", "SHAKE256", "SHAKE256"];
SLH.forEach((v, i) => {
  OIDS[`${SIG}${20 + i}`] = { name: `SLH-DSA-${v}`, family: "SLH-DSA", param: v };
  OIDS[`${SIG}${35 + i}`] = { name: `HashSLH-DSA-${v}-${SLH_PH[i]}`, family: "SLH-DSA", param: v };
});
[512, 768, 1024].forEach((n, i) => { OIDS[`2.16.840.1.101.3.4.4.${i + 1}`] = { name: `ML-KEM-${n}`, family: "ML-KEM", param: String(n) }; });

// Firmas compuestas ML-DSA + tradicional. Fuente: draft-ietf-lamps-pq-composite-sigs-19, sección 6
// (arco 1.3.6.1.5.5.7.6, asignación temprana de IANA). Son de BORRADOR: se marcan como provisionales.
export const COMPOSITE_SOURCE = "draft-ietf-lamps-pq-composite-sigs-19";
[
  [37, "MLDSA44-RSA2048-PSS-SHA256"], [38, "MLDSA44-RSA2048-PKCS15-SHA256"], [39, "MLDSA44-Ed25519-SHA512"], [40, "MLDSA44-ECDSA-P256-SHA256"],
  [41, "MLDSA65-RSA3072-PSS-SHA512"], [42, "MLDSA65-RSA3072-PKCS15-SHA512"], [43, "MLDSA65-RSA4096-PSS-SHA512"], [44, "MLDSA65-RSA4096-PKCS15-SHA512"],
  [45, "MLDSA65-ECDSA-P256-SHA512"], [46, "MLDSA65-ECDSA-P384-SHA512"], [47, "MLDSA65-ECDSA-brainpoolP256r1-SHA512"], [48, "MLDSA65-Ed25519-SHA512"],
  [49, "MLDSA87-ECDSA-P384-SHA512"], [50, "MLDSA87-ECDSA-brainpoolP384r1-SHA512"], [51, "MLDSA87-Ed448-SHAKE256"], [52, "MLDSA87-RSA3072-PSS-SHA512"],
  [53, "MLDSA87-RSA4096-PSS-SHA512"], [54, "MLDSA87-ECDSA-P521-SHA512"],
].forEach(([n, id]) => {
  const [, ml, trad] = id.match(/^MLDSA(\d+)-(.+?)-(?:SHA\d+|SHAKE256)$/);
  OIDS[`1.3.6.1.5.5.7.6.${n}`] = { name: id, family: "composite", param: ml, components: [`ML-DSA-${ml}`, trad], provisional: true };
});

export const CURVES = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.3.132.0.10": "secp256k1",
};

export function pemBlocks(text) {
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  const out = [];
  let m;
  while ((m = re.exec(text))) {
    const b64 = m[1].replace(/[^A-Za-z0-9+/=]/g, "");
    const bin = atob(b64);
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    out.push(u);
  }
  return out;
}

const hex = (u) => [...u].map((b) => b.toString(16).padStart(2, "0")).join(":");
const EKU = { "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning", "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning" };
const KU = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];

// Extensiones X.509 v3 más relevantes para inventario: CA, usos, SAN e identificadores de clave.
function extensions(buf, node) {
  const ext = { ca: null, pathLen: null, keyUsage: [], extKeyUsage: [], san: [], ski: null, aki: null, other: [] };
  const seq = children(buf, node)[0];
  if (!seq) return ext;
  for (const e of children(buf, seq)) {
    const parts = children(buf, e);
    const id = oid(buf, parts[0]);
    const val = parts[parts.length - 1];
    const inner = buf.subarray(val.start, val.end);
    try {
      if (id === "2.5.29.19") {
        const bc = readTLV(inner, 0);
        ext.ca = false;
        for (const c of children(inner, bc)) {
          if (c.tag === 0x01) ext.ca = inner[c.start] !== 0;
          else if (c.tag === 0x02) ext.pathLen = inner[c.start];
        }
      } else if (id === "2.5.29.15") {
        const bs = readTLV(inner, 0);
        const bits = inner.subarray(bs.start + 1, bs.end);
        KU.forEach((k, i) => { if (bits[i >> 3] & (0x80 >> (i & 7))) ext.keyUsage.push(k); });
      } else if (id === "2.5.29.37") {
        for (const c of children(inner, readTLV(inner, 0))) { const o = oid(inner, c); ext.extKeyUsage.push(EKU[o] || o); }
      } else if (id === "2.5.29.17") {
        for (const c of children(inner, readTLV(inner, 0))) {
          if (c.tag === 0x82) ext.san.push(new TextDecoder().decode(inner.subarray(c.start, c.end)));
          else if (c.tag === 0x87) ext.san.push(c.len === 4 ? [...inner.subarray(c.start, c.end)].join(".") : "IPv6");
        }
      } else if (id === "2.5.29.14") {
        const os = readTLV(inner, 0); ext.ski = hex(inner.subarray(os.start, os.end));
      } else if (id === "2.5.29.35") {
        const k = children(inner, readTLV(inner, 0)).find((c) => c.tag === 0x80);
        if (k) ext.aki = hex(inner.subarray(k.start, k.end));
      } else ext.other.push(id);
    } catch { ext.other.push(id); }
  }
  return ext;
}

export function parseCertificate(der) {
  const buf = der instanceof Uint8Array ? der : new Uint8Array(der);
  try { return parseCertificateStrict(buf); }
  catch (e) {
    throw new Error(/ASN\.1|DER/.test(e.message) ? e.message : "No es un certificado X.509 válido (estructura inesperada)");
  }
}

function parseCertificateStrict(buf) {
  const cert = readTLV(buf, 0);
  if (cert.tag !== 0x30) throw new Error("No es un certificado DER");
  const [tbs, sigAlg] = children(buf, cert);
  if (!tbs || !sigAlg || tbs.tag !== 0x30) throw new Error("No es un certificado DER");
  const t = children(buf, tbs);
  if (t.length < 6) throw new Error("No es un certificado DER");
  let i = 0;
  if (t[0].tag === 0xa0) i++; // versión
  const serial = hex(buf.subarray(t[i].start, t[i].end)); i++;
  i++; // algoritmo de firma (repetido)
  const issuer = name(buf, t[i++]);
  const [nb, na] = children(buf, t[i++]);
  const subject = name(buf, t[i++]);
  const spki = t[i++];
  const [keyAlg, keyBits] = children(buf, spki);
  const ka = children(buf, keyAlg);
  const keyOid = oid(buf, ka[0]);
  const keyInfo = OIDS[keyOid] || { name: keyOid, family: "desconocido" };
  let keySize = null;
  let curve = null;
  let pubBytes = null;
  if (keyInfo.family === "RSA") {
    const bits = buf.subarray(keyBits.start + 1, keyBits.end);
    const seq = readTLV(bits, 0);
    const mod = readTLV(bits, seq.start);
    let n = mod.len;
    let p = mod.start;
    while (n > 0 && bits[p] === 0) { n--; p++; }
    keySize = n > 0 ? n * 8 - Math.clz32(bits[p]) + 24 : null;
  } else if (keyInfo.family === "EC" && ka[1] && ka[1].tag === 0x06) {
    const c = oid(buf, ka[1]);
    curve = CURVES[c] || c;
    keySize = { "P-256": 256, "P-384": 384, "P-521": 521, secp256k1: 256 }[curve] || null;
  } else if (keyInfo.family === "EC") {
    curve = "parámetros explícitos";
  } else if (keyInfo.family === "EdDSA") {
    keySize = keyInfo.name === "Ed25519" ? 256 : 456;
  } else if (keyBits && keyBits.len > 1) {
    pubBytes = keyBits.len - 1; // PQC y compuestos: tamaño de la clave pública codificada
  }
  const sigOid = oid(buf, children(buf, sigAlg)[0]);
  const sigInfo = OIDS[sigOid] || { name: sigOid, family: "desconocido" };
  const extNode = t.slice(i).find((n) => n.tag === 0xa3);
  const ext = extNode ? extensions(buf, extNode) : { ca: null, pathLen: null, keyUsage: [], extKeyUsage: [], san: [], ski: null, aki: null, other: [] };
  const selfSigned = issuer === subject && (!ext.aki || !ext.ski || ext.aki === ext.ski);
  return {
    serial, ext,
    subject, issuer, notBefore: time(buf, nb), notAfter: time(buf, na),
    keyOid, keyAlg: keyInfo.name, keyFamily: keyInfo.family, keySize, curve,
    sigOid, sigAlg: sigInfo.name, sigFamily: sigInfo.family, selfSigned, pubBytes,
    paramSet: keyInfo.param || null, components: keyInfo.components || sigInfo.components || null,
    provisional: !!(keyInfo.provisional || sigInfo.provisional),
  };
}
