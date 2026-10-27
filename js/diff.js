// Comparación de dos inventarios (actual frente a sesión o CBOM anterior).
import { CATEGORIES } from "./classify.js";
import { readiness } from "./report.js";

const key = (a) => a.name.toLowerCase();
const isVuln = (a) => a.category === "vulnerable";
const isRisk = (a) => a.category === "vulnerable" || a.category === "legacy";

export function diffInventories(prev, cur, now = Date.now()) {
  const P = new Map(prev.algorithms.map((a) => [key(a), a]));
  const C = new Map(cur.algorithms.map((a) => [key(a), a]));
  const added = [...C.values()].filter((a) => !P.has(key(a)));
  const removed = [...P.values()].filter((a) => !C.has(key(a)));
  const changed = [...C.values()].filter((a) => P.has(key(a)) && P.get(key(a)).category !== a.category).map((a) => ({ name: a.name, from: P.get(key(a)).category, to: a.category }));
  const certKey = (c) => `${c.cn || c.subject}|${new Date(c.notAfter).toISOString().slice(0, 10)}`;
  const pc = new Set(prev.certificates.map(certKey)), cc = new Set(cur.certificates.map(certKey));
  const pp = new Set(prev.protocols.map((p) => p.name)), cp = new Set(cur.protocols.map((p) => p.name));
  const rp = readiness(prev, now).score, rc = readiness(cur, now).score;
  const count = (inv, f) => inv.algorithms.filter(f).length;
  return {
    added, removed, changed,
    vulnerable: { prev: count(prev, isVuln), cur: count(cur, isVuln), delta: count(cur, isVuln) - count(prev, isVuln) },
    risk: { prev: count(prev, isRisk), cur: count(cur, isRisk), delta: count(cur, isRisk) - count(prev, isRisk) },
    readiness: { prev: rp, cur: rc, delta: rp === null || rc === null ? null : rc - rp },
    certs: { added: cur.certificates.filter((c) => !pc.has(certKey(c))).map((c) => c.cn || c.subject), removed: prev.certificates.filter((c) => !cc.has(certKey(c))).map((c) => c.cn || c.subject) },
    protocols: { added: [...cp].filter((n) => !pp.has(n)), removed: [...pp].filter((n) => !cp.has(n)) },
  };
}

const sign = (n) => (n > 0 ? `+${n}` : String(n));
export function diffMarkdown(d, label = "sesión anterior") {
  const L = ["## Comparación con " + label, ""];
  L.push(`- Algoritmos vulnerables (Shor): ${d.vulnerable.prev} → ${d.vulnerable.cur} (${sign(d.vulnerable.delta)})`);
  L.push(`- Vulnerables u obsoletos: ${d.risk.prev} → ${d.risk.cur} (${sign(d.risk.delta)})`);
  L.push(`- Indicador de preparación PQC: ${d.readiness.prev ?? "sin datos"} → ${d.readiness.cur ?? "sin datos"}${d.readiness.delta === null ? "" : ` (${sign(d.readiness.delta)})`}`);
  L.push(`- Algoritmos añadidos: ${d.added.map((a) => `${a.name} (${CATEGORIES[a.category].short})`).join(", ") || "ninguno"}`);
  L.push(`- Algoritmos retirados: ${d.removed.map((a) => `${a.name} (${CATEGORIES[a.category].short})`).join(", ") || "ninguno"}`);
  L.push(`- Clasificación cambiada: ${d.changed.map((c) => `${c.name}: ${CATEGORIES[c.from].short} → ${CATEGORIES[c.to].short}`).join(", ") || "ninguno"}`);
  L.push(`- Certificados añadidos: ${d.certs.added.join(", ") || "ninguno"} · retirados: ${d.certs.removed.join(", ") || "ninguno"}`);
  L.push(`- Protocolos añadidos: ${d.protocols.added.join(", ") || "ninguno"} · retirados: ${d.protocols.removed.join(", ") || "ninguno"}`);
  return L.join("\n") + "\n";
}
