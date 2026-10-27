// Pruebas de extremo a extremo de v0.3 (Playwright): PQC/compuestos, include, sesión, comparación e importación de CBOM.
// Uso: node tests/e2e-v03.mjs  (BASE y SHOTS como en tests/e2e.mjs)
import { chromium } from "playwright";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.env.BASE || "http://127.0.0.1:8765/";
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const fails = [];
let passed = 0;
const check = (cond, msg) => { if (cond) passed++; else { fails.push(msg); console.error("FALLO:", msg); } };
const dir = join(tmpdir(), "cbom-v03"); mkdirSync(dir, { recursive: true });
const tmp = (name, data) => { const p = join(dir, name); writeFileSync(p, data); return p; };
const shot = async (page, name, sel) => { if (!SHOTS) return; await page.waitForTimeout(700); await page.evaluate(() => { document.querySelector("#toast").hidden = true; }); if (sel) await (await page.$(sel)).screenshot({ path: `${SHOTS}/${name}.png` }); else await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true }); };

const browser = await chromium.launch();
async function session(opts, fn) {
  const ctx = await browser.newContext({ ...opts, acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(BASE);
  await page.waitForSelector("#view-inventario h1");
  try { await fn(page); } finally { check(errors.length === 0, `errores de consola (${opts.tag}): ${errors.join(" | ")}`); await ctx.close(); }
}
const rows = (page) => page.evaluate(() => [...document.querySelectorAll("#view-inventario .cols-src.list-row")].map((r) => ({ name: r.querySelector(".name").firstChild.textContent, warn: r.children[3].textContent })));
const pick = async (page, sel, files) => { const [fc] = await Promise.all([page.waitForEvent("filechooser"), page.click(sel)]); await fc.setFiles(files); await page.waitForTimeout(300); };
const dl = async (page, sel) => { const [d] = await Promise.all([page.waitForEvent("download"), page.click(sel)]); return readFileSync(await d.path(), "utf8"); };
async function noOverflow(page, tag) {
  const o = await page.evaluate(() => { const w = document.documentElement.clientWidth; return { sw: document.documentElement.scrollWidth, w }; });
  check(o.sw <= o.w + 1, `desbordamiento horizontal ${tag}: ${o.sw}>${o.w}`);
}

await session({ viewport: { width: 1280, height: 900 }, tag: "v03" }, async (page) => {
  // 1. Certificados PQC y compuestos de las muestras
  await page.click("[data-act=samples]");
  await page.waitForSelector("#alg-list .list-row");
  const certText = await page.evaluate(() => [...document.querySelectorAll(".cols-cert.list-row")].map((r) => r.textContent).join("\n"));
  check(/pasarela-hibrida[\s\S]*MLDSA65-ECDSA-P256-SHA512/.test(certText), "compuesto visible con su algoritmo");
  check(/OID provisional \(borrador IETF\)/.test(certText) && /Compuesto: ML-DSA-65 \+ ECDSA-P256/.test(certText), "compuesto marcado como provisional");
  check(/kem-pagos[\s\S]*ML-KEM-768/.test(certText) && /firma-archivo[\s\S]*SLH-DSA-SHA2-128s/.test(certText), "certificados ML-KEM y SLH-DSA");
  check((certText.match(/Sin SubjectAltName/g) || []).length === 1 && /intranet-legada[^\n]*Sin SubjectAltName/.test(certText), "aviso SAN solo en el ejemplo defectuoso");
  const badge = await page.evaluate(() => [...document.querySelectorAll(".cols-cert.list-row")].find((r) => r.textContent.includes("pasarela-hibrida")).querySelector(".badge").className);
  check(badge.includes("c-hybrid"), "compuesto clasificado híbrido");
  if (SHOTS) { await page.evaluate(() => [...document.querySelectorAll("#view-inventario h2")].find((h) => h.textContent === "Certificados").scrollIntoView()); await shot(page, "inventario-certificados-pqc-claro", "#view-inventario .section:has(.cols-cert)"); }

  // 2. Sesión: guardar con las muestras y un estado del plan
  await page.click(".tabs [data-view=plan]");
  await (await page.$("[data-status]")).selectOption("migrado");
  await page.click(".tabs [data-view=exportar]");
  const sessFull = await dl(page, "[data-act=session-save]");
  const sj = JSON.parse(sessFull);
  check(sj.schema === "cbom-pqc-lab/session" && sj.version === 1 && sj.sources.length >= 13 && sj.inventory.certificates.length === 8 && Object.values(sj.plan.statuses).includes("migrado") && sj.mosca.assets.length >= 3, "sesión guardada completa");
  const fullCbom = await dl(page, "[data-act=download]");
  writeFileSync(join(tmpdir(), "cbom-e2e-v03.json"), fullCbom);

  // Sesión previa más pequeña (sin los certificados PQC) para comparar
  const prev = { ...sj, sources: sj.sources.filter((s) => !/composite|kem|slh|politica/.test(s.name)) };
  delete prev.inventory;
  const prevPath = tmp("sesion-previa.json", JSON.stringify(prev));

  // 3. Comparación
  await pick(page, "[data-act=compare-pick]", [prevPath]);
  await page.waitForSelector(".diff-list");
  const cmp = await page.textContent("#compare");
  check(/sesion-previa\.json/.test(cmp) && /MLDSA65-ECDSA-P256-SHA512/.test(cmp) && /ML-KEM-768/.test(cmp), "comparación: algoritmos añadidos");
  check(await page.evaluate(() => /^\+\d+$/.test([...document.querySelectorAll(".diff-kv > div")][2].querySelector("b").textContent)), "comparación: indicador sube");
  check(await page.isVisible(".diff-kv .tone-good"), "comparación: tono positivo visible");
  await shot(page, "comparar-cbom-claro", "#compare");
  const md = await dl(page, "[data-act=report-md]");
  check(/## Comparación con sesion-previa\.json/.test(md) && /Algoritmos añadidos: .*ML-KEM-768/.test(md), "informe con comparación");
  await page.evaluate(() => { window.print = () => { window.__printed = true; }; });
  await page.click("[data-act=report-print]");
  check(await page.evaluate(() => /Comparación/.test(document.querySelector("#print-report").textContent)), "informe imprimible con comparación");
  // Comparación con un CBOM anterior
  const oldCbom = tmp("cbom-anterior.cdx.json", JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "cryptographic-asset", "bom-ref": "a", name: "Camellia-128", cryptoProperties: { assetType: "algorithm" } }, { type: "cryptographic-asset", "bom-ref": "b", name: "RSA-2048", cryptoProperties: { assetType: "algorithm" } }] }));
  await pick(page, "[data-act=compare-pick]", [oldCbom]);
  const cmp2 = await page.textContent("#compare");
  check(/cbom-anterior/.test(cmp2) && await page.evaluate(() => [...document.querySelectorAll(".diff-item.rm .name")].some((n) => n.textContent === "Camellia-128")), "comparación con CBOM: Camellia-128 retirado");
  // Referencia no válida
  await pick(page, "[data-act=compare-pick]", [tmp("roto.json", "{nope")]);
  check(/no es JSON válido/.test(await page.textContent("#compare")), "comparación: error legible con JSON roto");
  // La comparación persiste tras recargar
  await page.reload(); await page.waitForSelector("#view-exportar.is-active h1");
  check(await page.isVisible(".diff-kv"), "comparación persiste tras recargar");
  await page.click("[data-act=compare-clear]");
  check(!(await page.isVisible(".diff-kv")), "quitar comparación");

  // 4. Abrir sesión: errores amables y apertura correcta
  await pick(page, "[data-act=session-open]", [tmp("no-sesion.json", JSON.stringify({ hola: 1 }))]);
  check(/No es una sesión/.test(await page.textContent(".errs-box")), "sesión: error de esquema legible");
  await pick(page, "[data-act=session-open]", [tmp("futura.json", JSON.stringify({ ...sj, version: 7 }))]);
  check(/más reciente/.test(await page.textContent(".errs-box")), "sesión: versión futura avisada");
  await pick(page, "[data-act=session-open]", [tmp("estado-malo.json", JSON.stringify({ ...sj, plan: { statuses: { x: "hecho" } }, sources: [{ name: 3 }] }))]);
  const eb = await page.textContent(".errs-box");
  check(/Estado del plan/.test(eb) && /Fuente n\.º 1/.test(eb), "sesión: lista todos los errores");
  await shot(page, "sesion-errores-claro", "#view-exportar .section:has(.errs-box)");
  page.once("dialog", (d) => d.accept());
  await page.click("[data-act=reset]");
  await page.waitForTimeout(200);
  await page.click(".tabs [data-view=exportar]");
  await pick(page, "[data-act=session-open]", [tmp("sesion-completa.json", sessFull)]);
  await page.waitForSelector("#view-inventario.is-active #alg-list");
  check((await rows(page)).length === sj.sources.length, "sesión abierta: fuentes restauradas");
  await page.click(".tabs [data-view=plan]");
  check(await page.evaluate(() => [...document.querySelectorAll("[data-status]")].some((s) => s.value === "migrado")), "sesión abierta: estados del plan restaurados");
  // Soltar un fichero de sesión en Inventario también la abre
  await page.click(".tabs [data-view=inventario]");
  await page.evaluate((txt) => { const dt = new DataTransfer(); dt.items.add(new File([txt], "sesion.json")); document.querySelector("#drop").dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true })); }, JSON.stringify(prev));
  await page.waitForTimeout(400);
  check((await rows(page)).length === prev.sources.length, "sesión soltada en Inventario se abre");

  // 5. include: fusión en el mismo paso y carga posterior
  await page.click("[data-act=clear-sources]");
  const main = tmp("nginx-pagos.conf", "server {\n  listen 443 ssl;\n  include snippets/tls-pqc.conf;\n  include conf.d/cifrados-*.conf;\n  ssl_protocols TLSv1.3;\n}\n");
  const inc1 = tmp("tls-pqc.conf", "ssl_ecdh_curve X25519MLKEM768:X25519;\n");
  await pick(page, "[data-act=pick]", [main, inc1]);
  let rs = await rows(page);
  check(rs.length === 1 && rs[0].name === "nginx-pagos.conf", "include: el incluido se fusiona y no aparece como fuente aparte");
  check(/Include fusionado: tls-pqc\.conf/.test(rs[0].warn) && /sin fichero \(conf\.d\/cifrados-\*\.conf\)/.test(rs[0].warn), "include: fusionado y aviso del que falta");
  check(/X25519MLKEM768/.test(await page.textContent("#alg-list")), "include: algoritmos del incluido inventariados");
  check(await page.isVisible("[data-act=load-includes]"), "include: botón para cargar los que faltan");
  await shot(page, "include-pendiente-claro", "#view-inventario .section:has(.cols-src)");
  const inc2 = tmp("cifrados-pagos.conf", "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;\n");
  const stray = tmp("ajeno.conf", "ssl_ciphers RC4-SHA;\n");
  await pick(page, "[data-act=load-includes]", [inc2, stray]);
  rs = await rows(page);
  check(rs.length === 1 && /cifrados-pagos\.conf/.test(rs[0].warn) && !/sin fichero/.test(rs[0].warn), "include: carga posterior fusiona el que faltaba");
  check(!(await page.isVisible("[data-act=load-includes]")), "include: botón desaparece al completarse");
  check(/ChaCha20-Poly1305/.test(await page.textContent("#alg-list")) && !/RC4/.test(await page.textContent("#alg-list")), "include: solo se fusiona el fichero que coincide");
  // sshd Include en el mismo paso
  await pick(page, "[data-act=pick]", [tmp("sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nCiphers aes256-gcm@openssh.com\n"), tmp("50-pqc.conf", "KexAlgorithms mlkem768x25519-sha256\n")]);
  rs = await rows(page);
  check(rs.some((r) => r.name === "sshd_config" && /Include fusionado: 50-pqc\.conf/.test(r.warn)) && !rs.some((r) => r.name === "50-pqc.conf"), "include sshd fusionado en el mismo paso");
  await page.reload(); await page.waitForSelector("#alg-list");
  check(/mlkem768x25519-sha256/.test(await page.textContent("#alg-list")), "include persiste tras recargar");

  // 6. Importar CBOM: certificados y protocolos restaurados
  await page.click("[data-act=clear-sources]");
  await pick(page, "[data-act=pick]", [tmp("cbom-completo.cdx.json", fullCbom)]);
  const nCert = await page.$$eval(".cols-cert.list-row", (r) => r.length);
  const nProto = await page.$$eval(".cols-proto.list-row", (r) => r.length);
  check(nCert === 8 && nProto === 5, `CBOM importado: ${nCert} certificados y ${nProto} protocolos`);
  check(/Importado de CBOM/.test(await page.textContent("#view-inventario")) && /Ofrece PQC/.test(await page.textContent("#view-inventario")), "CBOM importado: detalle visible");
});

// Capturas en móvil y tema oscuro de las vistas nuevas
for (const [tag, opts] of [["movil-oscuro", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, colorScheme: "dark" }], ["escritorio-oscuro", { viewport: { width: 1360, height: 900 }, colorScheme: "dark" }]]) {
  await session({ ...opts, tag }, async (page) => {
    await page.click("[data-act=samples]");
    const nav = tag.startsWith("movil") ? ".tabbar" : ".tabs";
    await page.click(`${nav} [data-view=exportar]`);
    const sess = JSON.parse(await dl(page, "[data-act=session-save]"));
    sess.sources = sess.sources.filter((s) => !/composite|kem|slh|politica/.test(s.name)); delete sess.inventory;
    await pick(page, "[data-act=compare-pick]", [tmp(`previa-${tag}.json`, JSON.stringify(sess))]);
    await page.waitForSelector(".diff-list");
    await noOverflow(page, `${tag}/comparar`);
    await shot(page, `comparar-cbom-${tag}`, "#compare");
    await page.click(`${nav} [data-view=inventario]`);
    await page.waitForTimeout(900);
    await noOverflow(page, `${tag}/inventario`);
    if (SHOTS) await shot(page, `inventario-certificados-pqc-${tag}`, "#view-inventario .section:has(.cols-cert)");
  });
}

await browser.close();
console.log(`\n${passed} comprobaciones v0.3 superadas, ${fails.length} fallos.`);
process.exit(fails.length ? 1 : 0);
