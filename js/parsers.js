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
  unknown: "Formato no reconocido",
};

const strip = (t) => t.replace(/^\s*#.*$/gm, "");

export function detect(name, text, binary) {
  if (binary) return "cert";
  if (/ssl-enum-ciphers/.test(text)) return "nmap";
  if (/CONNECTED\(|Server certificate|Peer signature type|Negotiated TLS1\.3 group|New, TLSv/.test(text)) return "sclient";
  if (/-----BEGIN CERTIFICATE-----/.test(text) && !/\bssl_\w+|KexAlgorithms/.test(text)) return "cert";
  if (/^\s*(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs|HostKey)\s+\S/im.test(text) || /sshd/i.test(name)) return "sshd";
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
  try {
    if (type === "cert") {
      const ders = bytes ? [bytes] : pemBlocks(text);
      if (!ders.length) res.warnings.push("No se encontró ningún bloque CERTIFICATE.");
      for (const d of ders) res.certs.push(parseCertificate(d));
    } else if (type === "nginx") {
      const t = strip(text);
      const g = (k) => [...t.matchAll(new RegExp(`\\b${k}\\s+([^;]+);`, "g"))].map((m) => m[1].trim());
      const versions = g("ssl_protocols").flatMap(list);
      const suites = g("ssl_ciphers").flatMap((v) => list(v.replace(/["']/g, ""))).filter((s) => !/^[!+-]|^(HIGH|MEDIUM|LOW|ALL|DEFAULT|aNULL|eNULL)$/.test(s));
      let groups = g("ssl_ecdh_curve").flatMap(list).filter((x) => x !== "auto");
      for (const c of g("ssl_conf_command")) {
        const m = c.match(/^(Groups|Curves)\s+(.+)$/i);
        if (m) groups = groups.concat(list(m[2]));
      }
      const p = tlsProtocol(`TLS · ${name}`, versions, suites, groups, []);
      res.protocols.push(p);
      groups.forEach((x) => addAlg(x, "Grupo de intercambio TLS"));
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Suite ${s.name}`)));
      if (versions.some((v) => /TLSv1(\.0|\.1)?$/.test(v))) res.warnings.push("Protocolos TLS 1.0/1.1 habilitados.");
      if (!groups.length) res.warnings.push("Sin ssl_ecdh_curve: el grupo efectivo depende de la versión de OpenSSL.");
      g("ssl_certificate").forEach((c) => res.warnings.push(`Referencia a certificado ${c}: cárgalo para analizar su clave.`));
    } else if (type === "sshd") {
      const t = strip(text);
      const g = (k) => [...t.matchAll(new RegExp(`^\\s*${k}\\s+(.+)$`, "gim"))].map((m) => m[1].trim());
      const kex = g("KexAlgorithms").flatMap((v) => v.split(",")).map((x) => x.replace(/^[+\-^]/, "").trim()).filter(Boolean);
      const hk = g("HostKeyAlgorithms").flatMap((v) => v.split(",")).map((x) => x.replace(/^[+\-^]/, "").trim()).filter(Boolean);
      const ci = g("Ciphers").flatMap((v) => v.split(",")).map((x) => x.replace(/^[+\-^]/, "").trim()).filter(Boolean);
      const mac = g("MACs").flatMap((v) => v.split(",")).map((x) => x.replace(/^[+\-^]/, "").trim()).filter(Boolean);
      res.protocols.push({ type: "ssh", name: `SSH · ${name}`, versions: ["2.0"], kex, hostKeys: hk, ciphers: ci, macs: mac });
      kex.forEach((x) => addAlg(x, "SSH KexAlgorithms"));
      hk.forEach((x) => addAlg(x, "SSH HostKeyAlgorithms"));
      ci.forEach((x) => addAlg(x, "SSH Ciphers"));
      mac.forEach((x) => addAlg(x, "SSH MACs"));
      if (!kex.length) res.warnings.push("Sin KexAlgorithms explícito: se usan los valores por defecto de OpenSSH.");
    } else if (type === "policy") {
      const t = strip(text);
      const g = (k) => [...t.matchAll(new RegExp(`^\\s*${k}\\s*=\\s*(.+)$`, "gim"))].map((m) => m[1].trim());
      const groups = g("(?:Groups|Curves)").flatMap((v) => v.split(":")).filter(Boolean);
      const suites = g("Ciphersuites").flatMap((v) => v.split(":")).filter(Boolean);
      const cs = g("CipherString").flatMap((v) => v.split(/[:+]/)).filter((x) => x && !/^[!@-]|^(HIGH|MEDIUM|DEFAULT|ALL)$/i.test(x));
      const sigs = g("SignatureAlgorithms").flatMap((v) => v.split(/[:+]/)).filter(Boolean);
      const versions = g("MinProtocol");
      const p = tlsProtocol(`Política TLS · ${name}`, versions.map((v) => `≥ ${v}`), suites, groups, sigs);
      res.protocols.push(p);
      groups.forEach((x) => addAlg(x, "Groups"));
      p.suites.forEach((s) => s.algs.forEach((a) => addAlg(a, `Ciphersuites ${s.name}`)));
      cs.forEach((x) => addAlg(x.replace(/^AESGCM$/i, "AES-GCM").replace(/^EECDH$/i, "ECDHE"), "CipherString"));
      sigs.forEach((x) => addAlg(x, "SignatureAlgorithms"));
    } else if (type === "sclient") {
      for (const d of pemBlocks(text)) res.certs.push(parseCertificate(d));
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
    } else {
      res.warnings.push("No se reconoce el formato. Admite PEM/DER, nginx.conf, sshd_config, openssl.cnf, s_client y nmap.");
    }
  } catch (e) {
    res.warnings.push(`Error al analizar: ${e.message}`);
  }
  return res;
}
