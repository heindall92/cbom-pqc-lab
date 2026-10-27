// Analizadores de ficheros de configuración y salidas de herramientas. Todo se procesa en local.
import { pemBlocks, parseCertificate } from "./x509.js";
import { decomposeSuite } from "./classify.js";

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
  const { name, text, bytes } = file;
  const type = detect(name, text || "", !!bytes);
  const res = { source: name, type, typeLabel: TYPES[type], protocols: [], algs: [], certs: [], warnings: [] };
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
      const inc = g("include");
      if (inc.length) res.warnings.push(`Directiva include (${inc.slice(0, 3).join(", ")}): esos ficheros no se siguen; cárgalos también para un inventario completo.`);
      uniq(g("ssl_certificate")).forEach((c) => res.warnings.push(`Referencia a certificado ${unquote(c)}: cárgalo para analizar su clave.`));
    } else if (type === "sshd") {
      // Las directivas tras "Match" solo aplican a ese bloque; se etiquetan con su condición.
      const kw = { kexalgorithms: "kex", hostkeyalgorithms: "hostKeys", ciphers: "ciphers", macs: "macs" };
      const out = { kex: [], hostKeys: [], ciphers: [], macs: [] };
      const ctxName = { kex: "KexAlgorithms", hostKeys: "HostKeyAlgorithms", ciphers: "Ciphers", macs: "MACs" };
      const removed = [], modifiers = new Set(), includes = [], matches = [];
      let match = null;
      for (const line of strip(text).split("\n")) {
        const m = line.match(/^\s*([A-Za-z]+)(?:\s*=\s*|\s+)(.+?)\s*$/);
        if (!m) continue;
        const k = m[1].toLowerCase();
        if (k === "match") { match = m[2]; matches.push(m[2]); continue; }
        if (k === "include") { includes.push(m[2]); continue; }
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
      if (includes.length) res.warnings.push(`Include ${includes.join(", ")}: no se sigue; carga esos ficheros también.`);
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
      const bom = JSON.parse(text);
      if (bom.bomFormat !== "CycloneDX" || !Array.isArray(bom.components)) throw new Error("JSON CycloneDX sin componentes");
      let n = 0;
      for (const c of bom.components) {
        const ap = c?.cryptoProperties;
        if (c?.type !== "cryptographic-asset" || ap?.assetType !== "algorithm" || !c.name) continue;
        const ctxProp = (c.properties || []).find((p) => p.name === "cbom-pqc-lab:contextos")?.value;
        (ctxProp ? ctxProp.split("; ").slice(0, 4) : ["CBOM importado"]).forEach((ctx) => addAlg(String(c.name), `${ctx} (importado)`));
        n++;
      }
      res.warnings.push(`CBOM CycloneDX ${bom.specVersion || "?"} importado: ${n} algoritmos reclasificados con las reglas actuales. Certificados y protocolos no se reconstruyen; carga las fuentes originales para el detalle.`);
    } else {
      res.warnings.push("No se reconoce el formato. Admite PEM/DER, nginx.conf, sshd_config, openssl.cnf, s_client, nmap, openssl ciphers -v y CBOM CycloneDX (JSON).");
    }
  } catch (e) {
    res.warnings.push(`Error al analizar: ${/^[A-Z][a-z]+Error$/.test(e.name) && e.name !== "Error" ? "contenido con formato inesperado" : e.message}.`);
  }
  return res;
}
