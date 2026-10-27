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

export function evaluate(x, y, z) {
  const X = Number(x) || 0, Y = Number(y) || 0, Z = Number(z) || 0;
  const margin = X + Y - Z;
  let level;
  if (margin > 0) level = "critical";
  else if (margin > -2) level = "warning";
  else level = "ok";
  return { X, Y, Z, sum: X + Y, margin, critical: margin > 0, level };
}

export const LEVELS = {
  critical: { label: "Deuda criptográfica crítica", short: "Crítica" },
  warning: { label: "En el límite (menos de 2 años de holgura)", short: "Límite" },
  ok: { label: "Con holgura", short: "Holgura" },
};
