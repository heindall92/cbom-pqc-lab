// Exportación CycloneDX 1.6 (CBOM) con componentes cryptographic-asset.
import { CATEGORIES } from "./classify.js";

const PRIM_FUNCS = {
  "key-agree": ["keygen", "keyderive"], kem: ["keygen", "encapsulate", "decapsulate"],
  signature: ["keygen", "sign", "verify"], pke: ["encrypt", "decrypt"], ae: ["encrypt", "decrypt", "tag"],
  "block-cipher": ["encrypt", "decrypt"], "stream-cipher": ["encrypt", "decrypt"], hash: ["digest"], mac: ["tag"],
};

const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : "00000000-0000-4000-8000-" + Date.now().toString(16).padStart(12, "0").slice(-12));

export function buildCbom(inv, plan, meta = {}) {
  const planById = Object.fromEntries(plan.map((p) => [p.id, p]));
  const components = [];
  const deps = [];
  for (const a of inv.algorithms) {
    const ap = { primitive: a.primitive || "unknown", executionEnvironment: "unknown", implementationPlatform: "unknown" };
    if (a.paramSet) ap.parameterSetIdentifier = String(a.paramSet);
    if (a.curve) ap.curve = a.curve;
    if (a.mode) ap.mode = a.mode;
    if (a.padding) ap.padding = a.padding;
    if (PRIM_FUNCS[a.primitive]) ap.cryptoFunctions = PRIM_FUNCS[a.primitive];
    if (Number.isInteger(a.classical)) ap.classicalSecurityLevel = a.classical;
    ap.nistQuantumSecurityLevel = a.category === "vulnerable" || a.category === "legacy" ? 0 : Number.isInteger(a.nistQ) ? a.nistQ : undefined;
    if (ap.nistQuantumSecurityLevel === undefined) delete ap.nistQuantumSecurityLevel;
    const props = [
      { name: "cbom-pqc-lab:clasificacion", value: CATEGORIES[a.category].label },
      { name: "cbom-pqc-lab:contextos", value: a.contexts.join("; ") },
      { name: "cbom-pqc-lab:fuentes", value: a.sources.join("; ") },
    ];
    const pl = planById[a.id];
    if (pl) {
      props.push({ name: "cbom-pqc-lab:prioridad", value: `P${pl.prio}` });
      props.push({ name: "cbom-pqc-lab:destino", value: `${pl.std}: ${pl.to}` });
    }
    components.push({
      type: "cryptographic-asset", "bom-ref": a.id, name: a.name, description: a.note,
      cryptoProperties: { assetType: "algorithm", algorithmProperties: ap }, properties: props,
    });
  }
  for (const c of inv.certificates) {
    const pkRef = `${c.id}-pubkey`;
    components.push({
      type: "cryptographic-asset", "bom-ref": pkRef, name: `Clave pública de ${c.cn}`,
      cryptoProperties: {
        assetType: "related-crypto-material", ...(c.keyOid ? { oid: c.keyOid } : {}),
        relatedCryptoMaterialProperties: { type: "public-key", algorithmRef: c.keyRef, ...(c.keySize ? { size: c.keySize } : {}), format: "SubjectPublicKeyInfo" },
      },
    });
    components.push({
      type: "cryptographic-asset", "bom-ref": c.id, name: c.cn,
      cryptoProperties: {
        assetType: "certificate",
        certificateProperties: {
          subjectName: c.subject, issuerName: c.issuer,
          notValidBefore: c.notBefore.toISOString(), notValidAfter: c.notAfter.toISOString(),
          signatureAlgorithmRef: c.sigRef, subjectPublicKeyRef: pkRef, certificateFormat: "X.509", certificateExtension: "crt",
        },
      },
      properties: [{ name: "cbom-pqc-lab:fuente", value: c.source }, ...(c.provisional ? [{ name: "cbom-pqc-lab:oid-provisional", value: "Firma compuesta con OID de borrador IETF (draft-ietf-lamps-pq-composite-sigs)" }] : [])],
    });
    deps.push({ ref: c.id, dependsOn: [pkRef, c.sigRef] }, { ref: pkRef, dependsOn: [c.keyRef] });
  }
  for (const p of inv.protocols) {
    const pp = { type: p.type };
    if (p.versions?.length) pp.version = p.versions.join(", ");
    if (p.type === "tls" && p.suites.length) pp.cipherSuites = p.suites.map((s) => ({ name: s.name, algorithms: s.refs }));
    if (p.refs.length) pp.cryptoRefArray = p.refs;
    components.push({
      type: "cryptographic-asset", "bom-ref": p.id, name: p.name,
      cryptoProperties: { assetType: "protocol", protocolProperties: pp },
      properties: [{ name: "cbom-pqc-lab:pqc-ready", value: p.pqReady ? "true" : "false" }, { name: "cbom-pqc-lab:fuente", value: p.source }],
    });
    if (p.refs.length) deps.push({ ref: p.id, dependsOn: p.refs });
  }
  return {
    bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${uuid()}`, version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: "application", name: "CBOM & PQC Lab para Banca", version: "0.3.0" }] },
      component: { type: "application", "bom-ref": "sistema-evaluado", name: meta.name || "Inventario criptográfico" },
      properties: [{ name: "cbom-pqc-lab:mosca-z", value: String(meta.z ?? "") }],
    },
    components, dependencies: deps,
  };
}

// Comprobación estructural ligera en el navegador (la validación completa con el esquema oficial está en tests/).
export function checkCbom(bom) {
  const errs = [];
  if (bom.bomFormat !== "CycloneDX" || bom.specVersion !== "1.6") errs.push("Cabecera CycloneDX 1.6 incorrecta");
  if (!/^urn:uuid:[0-9a-f-]{36}$/.test(bom.serialNumber)) errs.push("serialNumber inválido");
  const refs = new Set();
  for (const c of bom.components) {
    if (refs.has(c["bom-ref"])) errs.push(`bom-ref duplicado: ${c["bom-ref"]}`);
    refs.add(c["bom-ref"]);
    if (c.type !== "cryptographic-asset" || !c.cryptoProperties?.assetType) errs.push(`Componente sin cryptoProperties: ${c.name}`);
  }
  for (const d of bom.dependencies) for (const r of [d.ref, ...d.dependsOn]) if (!refs.has(r)) errs.push(`Referencia rota: ${r}`);
  return errs;
}
