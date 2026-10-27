// Analizadores de ficheros de configuración y salidas de herramientas. Todo se procesa en local.
import { pemBlocks, parseCertificate } from "./x509.js";
import { decomposeSuite, classify } from "./classify.js";

export const TYPES = {
  cert: "Certificado X.509",
  nginx: "nginx.conf",
  sshd: "sshd_config",
  policy: "Política TLS (openssl.cnf)",
  sclient: "Salida openssl s_client",
  nmap: "Salida nmap ssl-enum-ciphers",
  ciphers: "Salida openssl ciphers -v",
  cbom: "CBOM CycloneDX (importado)",
  unknown: "Formato no reconocido",
};

// Quita comentarios '#' completos y al final de línea (fuera de comillas).
export function strip(t) {
  return t.split(/\r?\n/).map((line) => {
    let q = null;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === "#" && (i === 0 || /\s|;/.test(line[i - 1]))) return line.slice(0, i);
    }
    return line;
  }).join("\n");
}
const unquote = (v) => v.replace(/["']/g, "");
const uniq = (a) => { const seen = new Set(); return a.filter((x) => { const k = String(x).toLowerCase(); return seen.has(k) ? false : seen.add(k); }); };
// Selectores genéricos de OpenSSL: su expansión depende de la versión y del SECLEVEL.
const GENERIC = /^(HIGH|MEDIUM|LOW|EXPORT|ALL|DEFAULT|COMPLEMENTOFDEFAULT|COMPLEMENTOFALL|SUITEB\d*|aNULL|eNULL|NULL|kRSA|aRSA|aECDSA|kEECDH|kEDH|kDHE|kECDHE|EECDH|EDH|AESGCM|AESCCM|AES|CHACHA20|CAMELLIA|ARIA|SHA|SHA1|SHA256|SHA384|MD5|RSA|ECDSA|DSS|PSK|SRP|TLSv1(\.[0-3])?|SSLv3)$/i;
function splitCipherString(v) {
  const tokens = unquote(v).split(/[\s:,]+/).filter(Boolean);
  const suites = [], generic = [];
  for (const t of tokens) {
    if (/^[!\-+]/.test(t) || t.startsWith("@")) continue; // exclusiones, reordenaciones y @SECLEVEL/@STRENGTH
    const base = t.replace(/@.*$/, "");
    if (!base) continue;
    if (GENERIC.test(base) || base.includes("+")) generic.push(t); else suites.push(base);
  }
  return { suites, generic };
}
const GENERIC_WARN = (g) => `Selectores genéricos de OpenSSL (${uniq(g).slice(0, 6).join(", ")}): su expansión depende de la versión y del SECLEVEL y no se deduce aquí. Ejecuta openssl ciphers -v '<cadena>' en el servidor y pega la salida para listar las suites reales.`;

// Directivas include: nginx "include ruta;" y sshd "Include ruta [ruta...]". Devuelve las rutas declaradas.
export function findIncludes(type, text) {
  const t = strip(text || "");
  if (type === "nginx") return [...t.matchAll(/(?:^|[\s;{}])include\s+([^;]+);/g)].map((m) => unquote(m[1].trim()));
  if (type === "sshd") return [...t.matchAll(/^\s*include(?:\s*=\s*|\s+)(.+?)\s*$/gim)].flatMap((m) => unquote(m[1]).split(/\s+/)).filter(Boolean);
  return [];
}
const baseName = (p) => String(p).split(/[\\/]/).pop();
const globRe = (g) => new RegExp(`^${baseName(g).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");
// Fichero(s) cargado(s) que corresponden a una ruta de include, por nombre de fichero (admite * y ?).
export function matchInclude(pattern, files) {
  const re = globRe(pattern);
  return files.filter((f) => re.test(baseName(f.name)));
}
// Inserta el contenido de los includes encontrados entre "files" en el lugar de la directiva (hasta 3 niveles).
export function resolveIncludes(type, text, files, depth = 0, seen = new Set()) {
  const merged = [], missing = [];
  if (!files?.length || !["nginx", "sshd"].includes(type)) return { text, merged, missing: findIncludes(type, text) };
  const expand = (pattern) => {
    const all = matchInclude(pattern, files);
    if (!all.length) { missing.push(pattern); return null; }
    const hits = all.filter((f) => !seen.has(f.name)); // ya fusionado por otro include: no se repite
    return hits.map((f) => {
      seen.add(f.name); merged.push(f.name);
      const sub = depth < 2 ? resolveIncludes(type, f.text || "", files, depth + 1, seen) : { text: f.text || "", merged: [], missing: [] };
      merged.push(...sub.merged); missing.push(...sub.missing);
      return `\n# --- inicio include ${f.name} ---\n${sub.text}\n# --- fin include ${f.name} ---\n`;
    }).join("");
  };
  let out;
  if (type === "nginx") out = text.replace(/(^|[\s;{}])include\s+([^;#\n]+);/g, (all, pre, path) => { const r = expand(unquote(path.trim())); return r === null ? all : pre + r; });
  else out = text.split(/\r?\n/).map((line) => {
    const m = strip(line).match(/^\s*include(?:\s*=\s*|\s+)(.+?)\s*$/i);
    if (!m) return line;
    const paths = unquote(m[1]).split(/\s+/).filter(Boolean);
    const parts = paths.map((pth) => ({ pth, r: expand(pth) }));
    const left = parts.filter((x) => x.r === null).map((x) => x.pth);
    return (left.length ? `Include ${left.join(" ")}\n` : "") + parts.filter((x) => x.r !== null).map((x) => x.r).join("");
  }).join("\n");
  return { text: out, merged: [...new Set(merged)], missing: [...new Set(missing)] };
}

// Si un nginx.conf o sshd_config del mismo lote declara include de otro fichero del lote, se fusionan en una sola fuente.
export function mergeIncludes(files) {
  const used = new Set();
  const list = files.map((f) => {
    if (!f.text) return f;
    const type = detect(f.name, f.text, false);
    const pats = findIncludes(type, f.text);
    if (!pats.length) return f;
    const pool = files.filter((o) => o !== f && o.text);
    const hits = [...new Set(pats.flatMap((pt) => matchInclude(pt, pool)))];
    if (!hits.length) return f;
    hits.forEach((h) => used.add(h));
    return { ...f, includes: hits.map((h) => ({ name: h.name, text: h.text })) };
  });
  return { list: list.filter((f) => !used.has(f)), used: [...used] };
}

export function detect(name, text, binary) {
  if (binary) return "cert";
  if (/^\s*\{[\s\S]*"bomFormat"\s*:\s*"CycloneDX"/.test(text)) return "cbom";
  if (/^\s*[A-Z0-9_\-]+\s+(TLSv1(\.[0-3])?|SSLv3)\s+Kx=\S+\s+Au=\S+\s+Enc=/m.test(text)) return "ciphers";
  if (/ssl-enum-ciphers/.test(text)) return "nmap";
  if (/CONNECTED\(|Server certificate|Peer signature type|Negotiated TLS1\.3 group|New, TLSv/.test(text)) return "sclient";
  if (/-----BEGIN CERTIFICATE-----/.test(text) && !/\bssl_\w+|KexAlgorithms/.test(text)) return "cert";
  if (/^\s*(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs|HostKey)(\s*=\s*|\s+)\S/im.test(text) || /sshd/i.test(name)) return "sshd";
  if (/\bssl_(protocols|ciphers|ecdh_curve|conf_command)\b/.test(text) || /nginx/i.test(name)) return "nginx";
  if (/^\s*(Groups|CipherString|Ciphersuites|MinProtocol|SignatureAlgorithms|Curves)\s*=/im.test(text)) return "policy";
  return "unknown";
}

function list(v) {
  return v.split(/[\s,:]+/).map((x) => x.trim()).filter(Boolean);
}

function tlsProtocol(name, versions, suites, groups, sigs) {
  return { type: "tls", name, versions, suites: suites.map((s) => ({ name: s, algs: decomposeSuite(s).algs })), groups, sigs };
}

export function parseSource(file) {
  const { name, bytes } = file;
  let text = file.text;
  const type = detect(name, text || "", !!bytes);
  const res = { source: name, type, typeLabel: TYPES[type], protocols: [], algs: [], certs: [], warnings: [], includes: [], merged: [] };
  if ((type === "nginx" || type === "sshd") && text) {
    res.includes = findIncludes(type, text);
    if (file.includes?.length) {
      const r = resolveIncludes(type, text, file.includes);
      text = r.text; res.merged = r.merged; res.missingIncludes = r.missing;
    } else res.missingIncludes = res.includes;
  }
  const addAlg = (raw, ctx) => res.algs.push({ raw, ctx });
  const addCerts = (ders) => ders.forEach((d, i) => {
    try { res.certs.push(parseCertificate(d)); }
    catch (e) { res.warnings.push(`Certificado ${ders.length > 1 ? `n.º ${i + 1} ` : ""}ilegible: ${e.message}`); }
  });
  if (bytes ? !bytes.length : !String(text || "").trim()) {
    res.type = "unknown"; res.typeLabel = "Fichero vacío";
    res.warnings.push("El fichero está vacío.");
    return res;
  }
  try {
    if (type === "cert") {
      const ders = bytes ? [bytes] : pemBlocks(text);
      if (!ders.length) res.warnings.push("No se encontró ningún bloque CERTIFICATE.");
      addCerts(ders);
    } else if (type === "nginx") {
      const t = strip(text);
      const g = (k) => [...t.matchAll(new RegExp(`(?:^|[\\s;{}])${k}\\s+([^;]+);`, "g"))].map((m) => m[1].trim());
      const versions = uniq(g("ssl_protocols").flatMap((v) => list(unquote(v))));
      const cs = g("ssl_ciphers").map(splitCipherString);
      const suites = uniq(cs.flatMap((c) => c.suites));
      const generic = cs.flatMap((c) => c.generic);
      let groups = g("ssl_ecdh_curve").flatMap((v) => list(unquote(v))).filter((x) => x.toLowerCase() !== "auto");
      for (const c of g("ssl_conf_command")) {
        const m = unquote(c).match(/^(Groups|Curves)\s+(.+)$/i);
        if (m) groups = groups.concat(list(m[2]));
      }
      groups = uniq(groups);
      const p = tlsProtocol(`TLS · ${name}`, versions, suites, groups, []);
      res.protocols.push(p);
      groups.forEach((x) => addAlg(x, "Grupo de intercambio TLS"));
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Suite ${s.name}`)));
      if (versions.some((v) => /^(TLSv1(\.[01])?|SSLv[23])$/.test(v))) res.warnings.push("Protocolos TLS 1.0/1.1 o SSL habilitados.");
      if (!groups.length) res.warnings.push("Sin ssl_ecdh_curve: el grupo efectivo depende de la versión de OpenSSL.");
      if (generic.length) res.warnings.push(GENERIC_WARN(generic));
      if (res.merged.length) res.warnings.push(`Include fusionado: ${res.merged.join(", ")}.`);
      if (res.missingIncludes.length) res.warnings.push(`Directiva include sin fichero (${res.missingIncludes.slice(0, 3).join(", ")}): carga esos ficheros para fusionarlos en esta fuente.`);
      uniq(g("ssl_certificate")).forEach((c) => res.warnings.push(`Referencia a certificado ${unquote(c)}: cárgalo para analizar su clave.`));
    } else if (type === "sshd") {
      // Las directivas tras "Match" solo aplican a ese bloque; se etiquetan con su condición.
      const kw = { kexalgorithms: "kex", hostkeyalgorithms: "hostKeys", ciphers: "ciphers", macs: "macs" };
      const out = { kex: [], hostKeys: [], ciphers: [], macs: [] };
      const ctxName = { kex: "KexAlgorithms", hostKeys: "HostKeyAlgorithms", ciphers: "Ciphers", macs: "MACs" };
      const removed = [], modifiers = new Set(), matches = [];
      let match = null;
      for (const line of strip(text).split("\n")) {
        const m = line.match(/^\s*([A-Za-z]+)(?:\s*=\s*|\s+)(.+?)\s*$/);
        if (!m) continue;
        const k = m[1].toLowerCase();
        if (k === "match") { match = m[2]; matches.push(m[2]); continue; }
        if (k === "include") continue;
        const field = kw[k];
        if (!field) continue;
        let v = unquote(m[2]);
        const mod = v[0];
        if ("+-^".includes(mod)) { v = v.slice(1); modifiers.add(mod); }
        const items = v.split(",").map((x) => x.trim()).filter(Boolean);
        if (mod === "-") { removed.push(...items); continue; }
        const ctx = `SSH ${ctxName[field]}${match ? ` (Match ${match})` : ""}`;
        for (const x of items) { out[field].push(x); addAlg(x, ctx); }
      }
      for (const f in out) out[f] = uniq(out[f]);
      res.protocols.push({ type: "ssh", name: `SSH · ${name}`, versions: ["2.0"], ...out });
      if (!out.kex.length) res.warnings.push("Sin KexAlgorithms explícito: se usan los valores por defecto de OpenSSH.");
      if (removed.length) res.warnings.push(`Eliminados de los valores por defecto con '-' (no se inventarían): ${uniq(removed).join(", ")}.`);
      if (modifiers.has("+") || modifiers.has("^")) res.warnings.push("Listas con '+' o '^': además de lo indicado siguen activos los valores por defecto de OpenSSH, que no se inventarían.");
      if (res.merged.length) res.warnings.push(`Include fusionado: ${res.merged.join(", ")}.`);
      if (res.missingIncludes.length) res.warnings.push(`Include sin fichero (${res.missingIncludes.join(", ")}): carga esos ficheros para fusionarlos en esta fuente.`);
      if (matches.length) res.warnings.push(`Bloques Match (${matches.slice(0, 3).join("; ")}): sus algoritmos se marcan con la condición y solo aplican a esas conexiones.`);
    } else if (type === "policy") {
      const t = strip(text);
      const g = (k) => [...t.matchAll(new RegExp(`^\\s*${k}\\s*=\\s*(.+)$`, "gim"))].map((m) => m[1].trim());
      const groups = uniq(g("(?:Groups|Curves)").flatMap((v) => unquote(v).split(":")).map((x) => x.trim()).filter(Boolean));
      const suites = uniq(g("Ciphersuites").flatMap((v) => unquote(v).split(":")).map((x) => x.trim()).filter(Boolean));
      const cs = g("CipherString").map(splitCipherString);
      const sigs = uniq(g("SignatureAlgorithms").flatMap((v) => unquote(v).split(":")).flatMap((x) => (x.includes("+") ? x.split("+") : [x])).map((x) => x.trim()).filter(Boolean));
      const versions = g("MinProtocol").map(unquote);
      const p = tlsProtocol(`Política TLS · ${name}`, versions.map((v) => `≥ ${v}`), uniq([...suites, ...cs.flatMap((c) => c.suites)]), groups, sigs);
      res.protocols.push(p);
      groups.forEach((x) => addAlg(x, "Groups"));
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Ciphersuites ${s.name}`)));
      sigs.forEach((x) => addAlg(x, "SignatureAlgorithms"));
      const generic = cs.flatMap((c) => c.generic);
      if (generic.length) res.warnings.push(GENERIC_WARN(generic));
      if (versions.some((v) => /^(TLSv1(\.[01])?|SSLv3)$/i.test(v))) res.warnings.push("MinProtocol permite TLS 1.0/1.1.");
    } else if (type === "sclient") {
      addCerts(pemBlocks(text));
      const ver = (text.match(/Protocol\s*:\s*(TLSv[\d.]+)/) || text.match(/New, (TLSv[\d.]+)/) || [])[1];
      const suite = (text.match(/Cipher(?: is|\s*:)\s*([A-Z0-9_\-]+)/) || [])[1];
      const group = (text.match(/Negotiated TLS1\.3 group:\s*(\S+)/) || text.match(/Server Temp Key:\s*([A-Za-z0-9\-]+)/) || [])[1];
      const peer = (text.match(/Peer signature type:\s*(\S+)/) || [])[1];
      const p = tlsProtocol(`TLS negociado · ${name}`, ver ? [ver] : [], suite ? [suite] : [], group ? [group] : [], peer ? [peer] : []);
      res.protocols.push(p);
      if (group) addAlg(group.replace(/^ECDH$/, "ECDHE"), "Grupo negociado");
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Suite negociada ${s.name}`)));
      if (peer) addAlg(peer.replace(/^RSA-PSS$/i, "RSASSA-PSS"), "Firma del servidor");
      if (!group) res.warnings.push("La salida no muestra el grupo de intercambio negociado.");
    } else if (type === "nmap") {
      const versions = [];
      const suites = [];
      const groups = new Set();
      let cur = null;
      for (const line of text.split(/\r?\n/)) {
        const v = line.match(/\|\s+(TLSv[\d.]+|SSLv\d):/);
        if (v) { cur = v[1]; versions.push(cur); continue; }
        const s = line.match(/\|\s+(TLS_[A-Z0-9_]+)\s*(?:\(([^)]+)\))?/);
        if (s) {
          suites.push(s[1]);
          const kx = (s[2] || "").trim();
          if (/^(secp|x25519|x448|ffdhe)/i.test(kx)) groups.add(kx.split(/\s/)[0]);
          else if (/^dh (\d+)/i.test(kx)) groups.add(`ffdhe${kx.match(/\d+/)[0]}`);
        }
      }
      const p = tlsProtocol(`TLS escaneado · ${name}`, versions, [...new Set(suites)], [...groups], []);
      res.protocols.push(p);
      groups.forEach((x) => addAlg(x, "Grupo observado"));
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Suite ${s.name}`)));
      if (versions.some((v) => /TLSv1\.[01]$|TLSv1\.0|SSL/.test(v))) res.warnings.push("Versiones de protocolo obsoletas expuestas.");
    } else if (type === "ciphers") {
      // openssl ciphers -v: "NOMBRE  TLSv1.2  Kx=ECDH  Au=RSA  Enc=AESGCM(256)  Mac=AEAD"
      const suites = [], versions = new Set();
      for (const line of text.split(/\r?\n/)) {
        const m = line.match(/^\s*([A-Z0-9_\-]+)\s+(TLSv1(?:\.[0-3])?|SSLv3)\s+Kx=/);
        if (m) { suites.push(m[1]); versions.add(m[2]); }
      }
      const p = tlsProtocol(`Suites OpenSSL · ${name}`, [...versions], uniq(suites), [], []);
      res.protocols.push(p);
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Suite ${s.name}`)));
      res.warnings.push("Lista de suites que admite la cadena; los grupos de intercambio se configuran aparte (Groups / ssl_ecdh_curve).");
    } else if (type === "cbom") {
      const r = importCbom(JSON.parse(text));
      res.algs.push(...r.algs); res.certs.push(...r.certs); res.protocols.push(...r.protocols); res.warnings.push(...r.warnings);
    } else {
      res.warnings.push("No se reconoce el formato. Admite PEM/DER, nginx.conf, sshd_config, openssl.cnf, s_client, nmap, openssl ciphers -v y CBOM CycloneDX (JSON).");
    }
  } catch (e) {
    res.warnings.push(`Error al analizar: ${/^[A-Z][a-z]+Error$/.test(e.name) && e.name !== "Error" ? "contenido con formato inesperado" : e.message}.`);
  }
  return res;
}

// Reconstruye algoritmos, certificados y protocolos de un CBOM CycloneDX (1.4-1.6) con cryptoProperties.
export function importCbom(bom) {
  if (!bom || bom.bomFormat !== "CycloneDX" || !Array.isArray(bom.components)) throw new Error("JSON CycloneDX sin componentes");
  const out = { algs: [], certs: [], protocols: [], warnings: [] };
  const crypto = bom.components.filter((c) => c && c.type === "cryptographic-asset" && c.cryptoProperties && typeof c.name === "string");
  const byRef = new Map(crypto.map((c) => [c["bom-ref"], c]));
  const prop = (c, n) => (c.properties || []).find((p) => p?.name === n)?.value;
  const algName = (ref) => { const c = byRef.get(ref); return c?.cryptoProperties.assetType === "algorithm" ? c.name : null; };
  let na = 0, nc = 0, np = 0;
  for (const c of crypto) {
    if (c.cryptoProperties.assetType !== "algorithm") continue;
    const ctx = prop(c, "cbom-pqc-lab:contextos");
    (ctx ? ctx.split("; ").slice(0, 4) : ["CBOM importado"]).forEach((x) => out.algs.push({ raw: c.name, ctx: `${x} (importado)` }));
    na++;
  }
  for (const c of crypto) {
    const cp = c.cryptoProperties.certificateProperties;
    if (c.cryptoProperties.assetType !== "certificate" || !cp) continue;
    const nb = new Date(cp.notValidBefore), naf = new Date(cp.notValidAfter);
    if (isNaN(nb) || isNaN(naf)) { out.warnings.push(`Certificado ${c.name} sin fechas válidas: omitido.`); continue; }
    const pk = byRef.get(cp.subjectPublicKeyRef);
    const pkp = pk?.cryptoProperties?.relatedCryptoMaterialProperties || {};
    const keyAlg = algName(pkp.algorithmRef) || "desconocido";
    const sigAlg = algName(cp.signatureAlgorithmRef) || "desconocido";
    const subject = cp.subjectName || `CN=${c.name}`, issuer = cp.issuerName || "";
    out.certs.push({ imported: true, serial: null, ext: null, subject, issuer, notBefore: nb, notAfter: naf, keyOid: pk?.cryptoProperties?.oid || null, keyAlg, keyFamily: "importado", keySize: pkp.size || null, curve: null, sigOid: null, sigAlg, sigFamily: "importado", selfSigned: !!issuer && issuer === subject, provisional: /^MLDSA\d+-/i.test(keyAlg) || /^MLDSA\d+-/i.test(sigAlg) });
    nc++;
  }
  for (const c of crypto) {
    const pp = c.cryptoProperties.protocolProperties;
    if (c.cryptoProperties.assetType !== "protocol" || !pp) continue;
    const refs = (pp.cryptoRefArray || []).map(algName).filter(Boolean);
    const versions = pp.version ? String(pp.version).split(/,\s*/) : [];
    if (pp.type === "ssh") {
      const by = { kex: [], hostKeys: [], ciphers: [], macs: [] };
      for (const r of refs) { const cl = classify(r); (cl.role === "kex" || cl.role === "pke" ? by.kex : cl.role === "sig" ? by.hostKeys : cl.role === "mac" ? by.macs : by.ciphers).push(r); }
      out.protocols.push({ type: "ssh", name: c.name, versions, ...by });
    } else {
      const suites = (pp.cipherSuites || []).filter((s) => s?.name).map((s) => ({ name: s.name, algs: (s.algorithms || []).map(algName).filter(Boolean) }));
      const inSuites = new Set(suites.flatMap((s) => s.algs));
      const rest = refs.filter((r) => !inSuites.has(r));
      out.protocols.push({ type: pp.type === "tls" ? "tls" : String(pp.type || "tls"), name: c.name, versions, suites, imported: true, groups: rest.filter((r) => ["kex", "pke"].includes(classify(r).role)), sigs: rest.filter((r) => classify(r).role === "sig") });
    }
    np++;
  }
  out.warnings.push(`CBOM CycloneDX ${bom.specVersion || "?"} importado: ${na} algoritmos, ${nc} certificados y ${np} protocolos, reclasificados con las reglas actuales. Las extensiones X.509 no forman parte del CBOM.`);
  return out;
}
