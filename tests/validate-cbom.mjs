// Valida el CBOM generado con las muestras contra el esquema oficial CycloneDX 1.6.
// Uso: npm i --no-save ajv@8 ajv-formats && node tests/validate-cbom.mjs
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { SAMPLES } from "../js/samples.js";
import { parseSource } from "../js/parsers.js";
import { buildInventory } from "../js/inventory.js";
import { buildPlan } from "../js/plan.js";
import { buildCbom, checkCbom } from "../js/cbom.js";
import { ASSET_PRESETS, evaluate } from "../js/mosca.js";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const load = (f) => JSON.parse(readFileSync(new URL(`./schema/${f}`, import.meta.url)));
const ajv = new Ajv({ strict: false, logger: false, allErrors: true, validateFormats: true });
addFormats(ajv);
ajv.addSchema(load("spdx.schema.json"), "spdx.schema.json");
ajv.addSchema(load("jsf-0.82.schema.json"), "jsf-0.82.schema.json");
const validate = ajv.compile(load("bom-1.6.schema.json"));

const src = SAMPLES.map((s) => ({ name: s.name, parsed: parseSource(s.binary ? { name: s.name, bytes: Uint8Array.from(Buffer.from(s.b64, "base64")) } : { name: s.name, text: s.text }) }));
const inv = buildInventory(src);
const assets = ASSET_PRESETS.map((a) => ({ ...a, links: inv.protocols.map((p) => p.id) }));
const plan = buildPlan(inv, assets, 10);
const bom = JSON.parse(JSON.stringify(buildCbom(inv, plan, { z: 10 })));
let ok = validate(bom);
if (!ok) console.error(validate.errors);
const errs = checkCbom(bom);
if (errs.length) { console.error(errs); ok = false; }

// Pruebas de la lógica de Mosca
const cases = [[30, 6, 10, true], [5, 5, 10, false], [5, 6, 10, true], [0, 3, 10, false]];
for (const [x, y, z, exp] of cases) if (evaluate(x, y, z).critical !== exp) { console.error("Mosca", x, y, z); ok = false; }
if (evaluate(5, 4, 10).level !== "warning") { console.error("nivel límite"); ok = false; }

console.log(`${bom.components.length} componentes, ${plan.length} acciones del plan. Esquema 1.6: ${ok ? "VÁLIDO" : "ERRORES"}`);
process.exit(ok ? 0 : 1);
