// Sesión completa en JSON con esquema versionado: fuentes, inventario, activos de Mosca y estados del plan.
export const SESSION_SCHEMA = "cbom-pqc-lab/session";
export const SESSION_VERSION = 1;
const STATUSES = ["pendiente", "en-curso", "migrado", "aceptado"];
const CATS = ["vulnerable", "legacy", "hybrid", "pqc", "symmetric", "unknown"];

// Inventario serializable (fechas ISO) para guardar y comparar.
export function snapshotInventory(inv) {
  return {
    algorithms: inv.algorithms.map((a) => ({ id: a.id, name: a.name, category: a.category, role: a.role, contexts: a.contexts, sources: a.sources })),
    certificates: inv.certificates.map((c) => ({ id: c.id, cn: c.cn, subject: c.subject, issuer: c.issuer, notBefore: c.notBefore.toISOString(), notAfter: c.notAfter.toISOString(), keyAlg: c.keyAlg, keyRef: c.keyRef, sigAlg: c.sigAlg, sigRef: c.sigRef, provisional: !!c.provisional })),
    protocols: inv.protocols.map((p) => ({ id: p.id, name: p.name, type: p.type, versions: p.versions || [], pqReady: !!p.pqReady, classicalKex: p.classicalKex || [], refs: p.refs })),
  };
}
// Revive fechas de un inventario guardado.
export function reviveInventory(s) {
  return {
    algorithms: s.algorithms.map((a) => ({ contexts: [], sources: [], ...a })),
    certificates: s.certificates.map((c) => ({ ...c, notBefore: new Date(c.notBefore), notAfter: new Date(c.notAfter) })),
    protocols: s.protocols.map((p) => ({ classicalKex: [], refs: [], ...p })),
  };
}

export function buildSession({ state, inv, appVersion, now = new Date() }) {
  return {
    schema: SESSION_SCHEMA, version: SESSION_VERSION, app: { name: "CBOM & PQC Lab para Banca", version: appVersion }, savedAt: now.toISOString(),
    sources: state.sources.map((s) => ({ name: s.name, ...(s.b64 ? { b64: s.b64 } : { text: s.text }), ...(s.sample ? { sample: true } : {}), ...(s.includes?.length ? { includes: s.includes } : {}) })),
    inventory: snapshotInventory(inv),
    mosca: { z: state.z, zPreset: state.zPreset, assets: state.assets },
    plan: { statuses: state.statuses },
  };
}

const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
const str = (v) => typeof v === "string";
// Devuelve { ok, errors[], session }. Los mensajes están pensados para mostrarse tal cual.
export function validateSession(raw) {
  let data = raw;
  const errors = [];
  if (str(raw)) {
    try { data = JSON.parse(raw); } catch { return { ok: false, errors: ["El fichero no es JSON válido."] }; }
  }
  if (!isObj(data)) return { ok: false, errors: ["El fichero no contiene un objeto de sesión."] };
  if (data.bomFormat === "CycloneDX") return { ok: false, errors: ["Es un CBOM CycloneDX, no una sesión. Cárgalo en Inventario o úsalo para comparar."] };
  if (data.schema !== SESSION_SCHEMA) return { ok: false, errors: ["No es una sesión de CBOM & PQC Lab (falta \"schema\": \"cbom-pqc-lab/session\")."] };
  if (!Number.isInteger(data.version)) errors.push("Falta la versión del esquema de sesión.");
  else if (data.version > SESSION_VERSION) errors.push(`La sesión usa el esquema v${data.version}, más reciente que el que admite esta versión (v${SESSION_VERSION}). Actualiza la aplicación.`);
  else if (data.version < 1) errors.push(`Versión de esquema no admitida: v${data.version}.`);
  if (!Array.isArray(data.sources)) errors.push("\"sources\" debe ser una lista.");
  else data.sources.forEach((s, i) => {
    if (!isObj(s) || !str(s.name) || !(str(s.text) || str(s.b64))) errors.push(`Fuente n.º ${i + 1}: necesita "name" y "text" o "b64".`);
    else if (str(s.b64) && !/^[A-Za-z0-9+/]*={0,2}$/.test(s.b64)) errors.push(`Fuente ${s.name}: "b64" no es Base64 válido.`);
  });
  if (data.mosca !== undefined) {
    if (!isObj(data.mosca)) errors.push("\"mosca\" debe ser un objeto.");
    else {
      if (data.mosca.z !== undefined && !(Number.isFinite(data.mosca.z) && data.mosca.z >= 1 && data.mosca.z <= 50)) errors.push("Mosca: Z debe ser un número entre 1 y 50.");
      if (data.mosca.assets !== undefined && !Array.isArray(data.mosca.assets)) errors.push("Mosca: \"assets\" debe ser una lista.");
      else (data.mosca.assets || []).forEach((a, i) => { if (!isObj(a) || !str(a.id) || !Number.isFinite(a.x) || !Number.isFinite(a.y)) errors.push(`Activo n.º ${i + 1}: necesita "id", "x" e "y" numéricos.`); });
    }
  }
  if (data.plan !== undefined) {
    if (!isObj(data.plan) || (data.plan.statuses !== undefined && !isObj(data.plan.statuses))) errors.push("\"plan.statuses\" debe ser un objeto.");
    else for (const [k, v] of Object.entries(data.plan.statuses || {})) if (!STATUSES.includes(v)) errors.push(`Estado del plan no válido para ${k}: "${v}".`);
  }
  if (data.inventory !== undefined) {
    const inv = data.inventory;
    if (!isObj(inv) || !["algorithms", "certificates", "protocols"].every((k) => Array.isArray(inv[k]))) errors.push("\"inventory\" debe tener las listas algorithms, certificates y protocols.");
    else {
      if (inv.algorithms.some((a) => !isObj(a) || !str(a.name) || !CATS.includes(a.category))) errors.push("Inventario: cada algoritmo necesita \"name\" y una \"category\" conocida.");
      if (inv.certificates.some((c) => !isObj(c) || isNaN(new Date(c.notAfter)) || isNaN(new Date(c.notBefore)))) errors.push("Inventario: certificados con fechas no válidas.");
    }
  }
  return { ok: !errors.length, errors, session: errors.length ? null : data };
}
