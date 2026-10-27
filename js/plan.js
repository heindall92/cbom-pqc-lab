// Plan de transición hacia NIST PQC, priorizado por el resultado de Mosca.
import { evaluate } from "./mosca.js";

function target(a, viaSsh, isCertKey) {
  if (a.category === "legacy") {
    if (a.role === "sym") return { std: "Retirada inmediata", to: "AES-256-GCM o ChaCha20-Poly1305", why: "Débil ya hoy, independientemente de la amenaza cuántica." };
    if (a.role === "mac") return { std: "Retirada inmediata", to: "SHA-256/384 o HMAC-SHA2 (EtM en SSH)", why: "Hash obsoleto." };
    if (a.role === "kex") return { std: "Retirada inmediata", to: viaSsh ? "mlkem768x25519-sha256" : "X25519MLKEM768", why: "KEX débil ya hoy." };
    return { std: "Retirada inmediata", to: "ML-DSA-65 (FIPS 204) o, de forma transitoria, RSA-PSS ≥ 3072", why: "Firma débil ya hoy." };
  }
  if (a.role === "kex") {
    return viaSsh
      ? { std: "FIPS 203 · ML-KEM", to: "mlkem768x25519-sha256", why: "KEX híbrido disponible en OpenSSH 9.9+. Protege lo que se transmite hoy frente a HNDL." }
      : { std: "FIPS 203 · ML-KEM", to: "X25519MLKEM768 (transición) → ML-KEM-768/1024", why: "Grupo híbrido TLS 1.3 soportado por OpenSSL 3.5+ y navegadores actuales. Neutraliza HNDL." };
  }
  if (a.role === "pke") return { std: "FIPS 203 · ML-KEM", to: "Eliminar suites TLS_RSA_*; solo TLS 1.3 con X25519MLKEM768", why: "El transporte RSA no tiene secreto hacia adelante: el peor caso HNDL." };
  if (a.role === "sig") {
    if (viaSsh) return { std: "FIPS 204 · ML-DSA (vigilar)", to: "Mantener ssh-ed25519; planificar claves de host PQC cuando estén estandarizadas en SSH", why: "La autenticación solo es atacable en tiempo real tras un CRQC; no sufre HNDL." };
    if (isCertKey === "root") return { std: "FIPS 204 / FIPS 205", to: "ML-DSA-87 o SLH-DSA para raíces de larga vida", why: "Las raíces viven más que los certificados finales: planificar la nueva jerarquía con antelación." };
    return { std: "FIPS 204 · ML-DSA", to: "ML-DSA-65 (o certificados compuestos/duales en transición)", why: "Requiere soporte de CA, HSM y clientes; ciclo largo de migración." };
  }
  return { std: "Revisar", to: "Evaluación manual", why: "Sin regla automática." };
}

// assets: [{id,name,x,y,links:[ids de protocolo o certificado]}]
export function buildPlan(inv, assets, z) {
  const items = [];
  const evals = Object.fromEntries(assets.map((a) => [a.id, evaluate(a.x, a.y, z)]));
  const rootCerts = new Set(inv.certificates.filter((c) => c.selfSigned).map((c) => c.keyRef));
  for (const a of inv.algorithms) {
    if (a.category !== "vulnerable" && a.category !== "legacy") continue;
    const carriers = [
      ...inv.protocols.filter((p) => p.refs.includes(a.id)).map((p) => p.id),
      ...inv.certificates.filter((c) => c.keyRef === a.id || c.sigRef === a.id).map((c) => c.id),
    ];
    const linked = assets.filter((as) => as.links.some((l) => carriers.includes(l)));
    const worst = linked.map((as) => ({ as, ev: evals[as.id] })).sort((p, q) => q.ev.margin - p.ev.margin)[0];
    const viaSsh = a.contexts.every((c) => c.startsWith("SSH"));
    const hndl = a.role === "kex" || a.role === "pke";
    let prio = 3;
    if (a.category === "legacy") prio = 1;
    else if (worst && worst.ev.critical && hndl) prio = 1;
    else if (worst && (worst.ev.critical || (worst.ev.level === "warning" && hndl))) prio = 2;
    const t = target(a, viaSsh, rootCerts.has(a.id) ? "root" : null);
    items.push({
      id: a.id, alg: a, prio, hndl, carriers, linked: linked.map((l) => l.name),
      worst: worst ? { name: worst.as.name, margin: worst.ev.margin, level: worst.ev.level } : null, ...t,
    });
  }
  items.sort((p, q) => p.prio - q.prio || (q.worst?.margin ?? -99) - (p.worst?.margin ?? -99) || p.alg.name.localeCompare(q.alg.name));
  return items;
}

export const PRIORITIES = {
  1: { label: "P1 · Inmediata", hint: "HNDL activo sobre datos con deuda crítica, o algoritmo débil ya hoy." },
  2: { label: "P2 · Planificar", hint: "Firma sobre activos críticos o intercambio de claves al límite." },
  3: { label: "P3 · Vigilar", hint: "Sin activo crítico vinculado. Incluir en la hoja de ruta de agilidad." },
};
