// Indicador de preparación PQC, estado de cadena X.509 e informe exportable (Markdown).
import { CATEGORIES, ROLES } from "./classify.js";
import { evaluate, LEVELS } from "./mosca.js";
import { PRIORITIES } from "./plan.js";
import { diffMarkdown } from "./diff.js";

const DAY = 864e5;
const cnOf = (dn) => (String(dn).match(/CN=([^,]+)/) || [])[1] || dn;

// Indicador orientativo propio de esta herramienta (no es una métrica estándar).
// Cada parte vale 0-100 y se pondera; las partes sin datos no cuentan.
export function readiness(inv, now = Date.now()) {
  const kexProtos = inv.protocols.filter((p) => (p.classicalKex?.length || p.pqReady));
  const certs = inv.certificates;
  const algs = inv.algorithms;
  const keyCat = (c) => algs.find((a) => a.id === c.keyRef)?.category;
  const parts = [
    { id: "kex", label: "Protocolos que ofrecen intercambio de claves PQC o híbrido", weight: 40, n: kexProtos.length, ok: kexProtos.filter((p) => p.pqReady).length },
    { id: "legacy", label: "Algoritmos que no están obsoletos hoy", weight: 30, n: algs.length, ok: algs.filter((a) => a.category !== "legacy").length },
    { id: "certpqc", label: "Certificados con clave PQC", weight: 15, n: certs.length, ok: certs.filter((c) => ["pqc", "hybrid"].includes(keyCat(c))).length },
    { id: "valid", label: "Certificados vigentes", weight: 15, n: certs.length, ok: certs.filter((c) => c.notAfter >= now && c.notBefore <= now).length },
  ].map((p) => ({ ...p, pct: p.n ? Math.round((p.ok / p.n) * 100) : null }));
  const used = parts.filter((p) => p.n);
  const w = used.reduce((s, p) => s + p.weight, 0);
  const score = w ? Math.round(used.reduce((s, p) => s + p.pct * p.weight, 0) / w) : null;
  return { score, parts };
}

// Cadena: busca el emisor entre los certificados cargados (por nombre y, si existen, AKI/SKI). No verifica firmas.
export function chainStatus(certs) {
  const out = {};
  for (const c of certs) {
    if (c.selfSigned) { out[c.id] = { kind: "root", label: "Raíz autofirmada" }; continue; }
    const issuer = certs.find((p) => p !== c && p.subject === c.issuer && (!c.ext?.aki || !p.ext?.ski || c.ext.aki === p.ext.ski));
    out[c.id] = issuer ? { kind: "linked", label: `Emisor cargado: ${issuer.cn}`, issuer: issuer.id } : { kind: "missing", label: `Emisor no cargado: ${cnOf(c.issuer)}` };
  }
  return out;
}

export function certIssues(c, now = Date.now()) {
  const out = [];
  const days = Math.floor((c.notAfter - now) / DAY);
  if (c.notBefore > now) out.push("Aún no es válido");
  if (days < 0) out.push(`Caducado hace ${-days} días`);
  else if (days <= 30) out.push(`Caduca en ${days} días`);
  if (/^(SHA1|MD5)with/i.test(c.sigAlg)) out.push(`Firmado con ${c.sigAlg}`);
  if (c.keyFamily === "RSA" && c.keySize && c.keySize < 2048) out.push(`RSA de ${c.keySize} bits`);
  if (c.ext && c.ext.ca !== true && !c.ext.san.length) out.push("Sin SubjectAltName");
  if (c.provisional) out.push("OID provisional (borrador IETF)");
  return out;
}

const mdEsc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const row = (cells) => `| ${cells.map(mdEsc).join(" | ")} |`;
const table = (head, rows) => (rows.length ? [row(head), row(head.map(() => "---")), ...rows.map(row)].join("\n") : "_Sin datos._");
const STATUS = { pendiente: "Pendiente", "en-curso": "En curso", migrado: "Migrado", aceptado: "Riesgo aceptado" };

export function buildMarkdown({ inv, plan, assets, z, statuses = {}, now = new Date(), diff = null, diffLabel }) {
  const r = readiness(inv, now.getTime());
  const ch = chainStatus(inv.certificates);
  const year = now.getFullYear();
  const L = [];
  L.push("# Informe de inventario criptográfico y transición PQC", "");
  L.push(`Generado el ${now.toISOString().slice(0, 10)} con CBOM & PQC Lab para Banca v0.3. Análisis local de ficheros y salidas de herramientas; no se han sondeado endpoints en vivo.`, "");
  L.push("## Resumen", "");
  L.push(`- Algoritmos: ${inv.algorithms.length} · Certificados: ${inv.certificates.length} · Configuraciones de protocolo: ${inv.protocols.length}`);
  for (const k of Object.keys(CATEGORIES)) { const n = inv.algorithms.filter((a) => a.category === k).length; if (n) L.push(`- ${CATEGORIES[k].label}: ${n}`); }
  L.push("", `**Indicador de preparación PQC: ${r.score === null ? "sin datos" : `${r.score}/100`}** (indicador orientativo propio de esta herramienta, no una métrica estándar).`, "");
  L.push(table(["Componente", "Peso", "Resultado"], r.parts.map((p) => [p.label, `${p.weight} %`, p.n ? `${p.ok}/${p.n} (${p.pct} %)` : "Sin datos"])), "");
  L.push("## Algoritmos", "");
  L.push(table(["Algoritmo", "Función", "Clasificación", "Fuentes"], [...inv.algorithms].sort((a, b) => CATEGORIES[a.category].order - CATEGORIES[b.category].order || a.name.localeCompare(b.name)).map((a) => [a.name, ROLES[a.role] || "—", CATEGORIES[a.category].label, a.sources.join(", ")])), "");
  L.push("## Certificados", "");
  L.push(table(["Sujeto", "Clave", "Firma", "Caduca", "Cadena", "Observaciones"], inv.certificates.map((c) => [c.cn, inv.algorithms.find((a) => a.id === c.keyRef)?.name || c.keyAlg, c.sigAlg, c.notAfter.toISOString().slice(0, 10), ch[c.id].label, certIssues(c, now.getTime()).join("; ") || "—"])), "");
  L.push("## Protocolos", "");
  L.push(table(["Configuración", "Versión", "Intercambio clásico", "PQC"], inv.protocols.map((p) => [p.name, p.versions?.join(", ") || "—", p.classicalKex.join(", ") || "Ninguno", p.pqReady ? "Ofrece" : "No"])), "");
  L.push("## Teorema de Mosca", "", `Supuesto de horizonte cuántico Z = ${z} años (${year + Number(z)}). Z es un supuesto, no un hecho; X e Y son estimaciones de la entidad.`, "");
  L.push(table(["Activo", "X", "Y", "X + Y", "Resultado"], assets.map((a) => { const e = evaluate(a.x, a.y, z); return [a.name, e.X, e.Y, e.sum, `${LEVELS[e.level].short} (${e.margin > 0 ? `exceso ${e.margin}` : `holgura ${-e.margin}`} años)`]; })), "");
  L.push("## Plan de transición", "");
  L.push(table(["Prioridad", "Algoritmo", "Destino", "Activo más expuesto", "Estado"], plan.map((i) => [PRIORITIES[i.prio].label, i.alg.name, `${i.std}: ${i.to}`, i.worst ? i.worst.name : "—", STATUS[statuses[i.id]] || "Pendiente"])), "");
  if (diff) L.push(diffMarkdown(diff, diffLabel));
  L.push("## Limitaciones", "");
  L.push("- No se verifican firmas de certificados. Los `include` solo se fusionan si se cargan los ficheros referidos (por nombre).");
  L.push("- Las firmas compuestas usan OID de borrador IETF (provisionales) y pueden cambiar al publicarse el RFC.");
  L.push("- Los selectores genéricos de OpenSSL (p. ej. `HIGH`) no se expanden: su resultado depende de la versión instalada.");
  L.push("- La prioridad del plan es orientativa y no constituye un dictamen de cumplimiento normativo.");
  return L.join("\n") + "\n";
}
