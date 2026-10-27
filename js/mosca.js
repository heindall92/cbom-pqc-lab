// Teorema de Mosca: si X + Y > Z, los datos que se cifran hoy seguirán siendo
// sensibles cuando exista un ordenador cuántico relevante (CRQC).

export const Z_PRESETS = [
  { id: "pesimista", label: "Pesimista", z: 6 },
  { id: "central", label: "Central", z: 10 },
  { id: "optimista", label: "Optimista", z: 15 },
];

export const ASSET_PRESETS = [
  { id: "hipoteca", name: "Expediente hipotecario", x: 30, y: 6, kind: "conf", hint: "Contrato, tasación y datos económicos durante toda la vida del préstamo." },
  { id: "credito", name: "Historial crediticio", x: 20, y: 5, kind: "conf", hint: "Scoring, impagos y consultas que alimentan decisiones de riesgo." },
  { id: "firma", name: "Firma transaccional", x: 10, y: 5, kind: "auth", hint: "Prueba de autorización de operaciones; el riesgo es la falsificación futura." },
  { id: "sesion", name: "Token de sesión", x: 0, y: 3, kind: "auth", hint: "Vida de minutos u horas; poco expuesto a HNDL." },
  { id: "log", name: "Log transaccional", x: 10, y: 4, kind: "conf", hint: "Registros de operaciones conservados por obligación regulatoria." },
];

export const MAX_YEARS = 200;

// Umbral de Z por debajo del cual el activo pasa a deuda crítica, y estado en cada escenario.
export function sensitivity(x, y) {
  const ev = evaluate(x, y, 0);
  return { threshold: ev.sum, byPreset: Z_PRESETS.map((p) => ({ ...p, ev: evaluate(x, y, p.z) })) };
}

export function evaluate(x, y, z) {
  // Entradas saneadas: años no negativos, finitos y con 2 decimales como máximo.
  const n = (v, max) => { const f = Number(v); return Number.isFinite(f) ? Math.round(Math.min(Math.max(f, 0), max) * 100) / 100 : 0; };
  const X = n(x, MAX_YEARS), Y = n(y, MAX_YEARS), Z = n(z, MAX_YEARS);
  const r = (v) => Math.round(v * 100) / 100;
  const margin = r(X + Y - Z);
  let level;
  if (margin > 0) level = "critical";
  else if (margin > -2) level = "warning";
  else level = "ok";
  return { X, Y, Z, sum: r(X + Y), margin, critical: margin > 0, level };
}

export const LEVELS = {
  critical: { label: "Deuda criptográfica crítica", short: "Crítica" },
  warning: { label: "En el límite (menos de 2 años de holgura)", short: "Límite" },
  ok: { label: "Con holgura", short: "Holgura" },
};
