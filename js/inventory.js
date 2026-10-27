// Construye el inventario deduplicado a partir de las fuentes analizadas.
import { classify } from "./classify.js";

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

export function certKeyName(c) {
  if (c.keyFamily === "RSA") return `RSA-${c.keySize}`;
  if (c.keyFamily === "EC") return `ECDSA-${c.curve}`;
  return c.keyAlg;
}

export function buildInventory(sources) {
  const algs = new Map();
  const certs = [];
  const protocols = [];
  const add = (raw, ctx, src) => {
    const c = classify(raw);
    const key = `alg-${slug(c.name)}`;
    if (!algs.has(key)) algs.set(key, { ...c, id: key, kind: "algorithm", contexts: new Set(), sources: new Set() });
    const a = algs.get(key);
    a.contexts.add(ctx);
    a.sources.add(src);
    return key;
  };
  for (const s of sources) {
    for (const a of s.parsed.algs) add(a.raw, a.ctx, s.name);
    for (const c of s.parsed.certs) {
      const keyRef = add(certKeyName(c), "Clave pública de certificado", s.name);
      const sigRef = add(c.sigAlg, "Firma de certificado", s.name);
      const cn = (c.subject.match(/CN=([^,]+)/) || [])[1] || c.subject;
      const id = `cert-${slug(cn)}-${slug(c.notAfter.toISOString().slice(0, 10))}`;
      if (!certs.find((x) => x.id === id)) certs.push({ ...c, id, kind: "certificate", cn, keyRef, sigRef, source: s.name });
    }
    for (const p of s.parsed.protocols) {
      const id = `proto-${slug(p.name)}`;
      const refs = new Set();
      const collect = (raws, ctx) => raws.forEach((r) => refs.add(add(r, ctx, s.name)));
      if (p.type === "tls") {
        collect(p.groups || [], "Grupo de intercambio TLS");
        p.suites.forEach((su) => { su.refs = su.algs.map((a) => add(a, `Suite ${su.name}`, s.name)); su.refs.forEach((r) => refs.add(r)); });
        collect(p.sigs || [], "SignatureAlgorithms");
      } else {
        collect(p.kex, "SSH KexAlgorithms"); collect(p.hostKeys, "SSH HostKeyAlgorithms");
        collect(p.ciphers, "SSH Ciphers"); collect(p.macs, "SSH MACs");
      }
      protocols.push({ ...p, id, kind: "protocol", refs: [...refs], source: s.name });
    }
  }
  const list = [...algs.values()].map((a) => ({ ...a, contexts: [...a.contexts], sources: [...a.sources] }));
  // Estado agregado de cada protocolo según su peor componente de intercambio de claves.
  for (const p of protocols) {
    const kex = p.refs.map((r) => list.find((a) => a.id === r)).filter((a) => a && (a.role === "kex" || a.role === "pke"));
    p.pqReady = kex.some((a) => a.category === "hybrid" || a.category === "pqc");
    p.classicalKex = kex.filter((a) => a.category === "vulnerable" || a.category === "legacy").map((a) => a.name);
  }
  return { algorithms: list, certificates: certs, protocols };
}
