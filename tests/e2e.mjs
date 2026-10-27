// Pruebas de extremo a extremo con Playwright (Chromium headless).
// Uso: npm i --no-save playwright && npx playwright install chromium && node tests/e2e.mjs
// Variables: BASE (por defecto http://127.0.0.1:8765/), SHOTS (carpeta de capturas, opcional).
import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.env.BASE || "http://127.0.0.1:8765/";
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const fails = [];
let passed = 0;
const check = (cond, msg) => { if (cond) passed++; else { fails.push(msg); console.error("FALLO:", msg); } };
const tmp = (name, data) => { const p = join(tmpdir(), name); writeFileSync(p, data); return p; };

const browser = await chromium.launch();

async function session(opts, fn) {
  const ctx = await browser.newContext({ ...opts, acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(BASE);
  await page.waitForSelector("#view-inventario h1");
  try { await fn(page, ctx); } finally {
    check(errors.length === 0, `errores de consola (${opts.tag}): ${errors.join(" | ")}`);
    await ctx.close();
  }
}

async function noOverflow(page, tag) {
  const o = await page.evaluate(() => {
    const w = document.documentElement.clientWidth;
    const bad = [...document.querySelectorAll(".view.is-active *")].filter((e) => { const r = e.getBoundingClientRect(); return r.width && r.right > w + 1 && !e.closest("pre, .json"); });
    return { sw: document.documentElement.scrollWidth, w, bad: bad.slice(0, 3).map((e) => e.className || e.tagName) };
  });
  check(o.sw <= o.w + 1 && !o.bad.length, `desbordamiento horizontal ${tag}: ${o.sw}>${o.w} ${o.bad.join(",")}`);
}

const tabs = ["inventario", "mosca", "plan", "exportar"];
const VIEWPORTS = [
  { tag: "escritorio", viewport: { width: 1360, height: 900 } },
  { tag: "movil", viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true },
];

for (const vp of VIEWPORTS) for (const scheme of ["light", "dark"]) {
  const tag = `${vp.tag}-${scheme}`;
  await session({ ...vp, colorScheme: scheme, tag }, async (page) => {
    check(await page.evaluate(() => document.documentElement.dataset.theme) === scheme, `tema inicial ${tag}`);
    await page.click("#view-inventario [data-act=samples]");
    await page.waitForSelector("#alg-list .list-row");
    const nav = vp.tag === "movil" ? ".tabbar" : ".tabs";
    check(await page.isVisible(nav), `navegación visible ${tag}`);
    for (const t of tabs) {
      await page.click(`${nav} [data-view=${t}]`);
      await page.waitForSelector(`#view-${t}.is-active h1`);
      await page.waitForTimeout(950);
      await noOverflow(page, `${tag}/${t}`);
      if (SHOTS) await page.screenshot({ path: `${SHOTS}/${tag}-${t}.png`, fullPage: true });
    }
  });
}

// Funcionalidad detallada (escritorio, claro)
await session({ viewport: { width: 1280, height: 900 }, tag: "funcional" }, async (page) => {
  // Estado vacío
  check(await page.isVisible("#view-inventario .empty"), "estado vacío inventario");
  // Muestras y clasificación
  await page.click("[data-act=samples]");
  const cat = async (name) => page.evaluate((n) => [...document.querySelectorAll("#alg-list .list-row")].find((r) => r.querySelector(".name").firstChild.textContent.trim() === n)?.querySelector(".badge")?.className, name);
  check((await cat("X25519MLKEM768"))?.includes("c-hybrid"), "X25519MLKEM768 híbrido");
  check((await cat("RSA-2048"))?.includes("c-vulnerable"), "RSA-2048 vulnerable");
  check((await cat("ML-DSA-65"))?.includes("c-pqc"), "ML-DSA-65 PQC");
  check((await cat("AES-256-GCM"))?.includes("c-symmetric"), "AES-256-GCM aceptable");
  check((await cat("3DES-EDE-CBC"))?.includes("c-legacy"), "3DES obsoleto");
  check((await cat("SHA-1"))?.includes("c-legacy"), "SHA-1 obsoleto");
  // Filtros y búsqueda
  await page.click("[data-filter=hybrid]");
  check((await page.$$("#alg-list .list-row")).length >= 1, "filtro híbrido");
  await page.click("[data-filter=all]");
  await page.fill("#q", "zzzz-no-existe");
  check(await page.isVisible("#alg-list .empty"), "búsqueda sin resultados");
  await page.fill("#q", "");
  // Pegado: varios malformados
  const paste = async (name, text) => {
    if (!(await page.isVisible("#paste-text"))) await page.click("#drop [data-act=paste]");
    await page.fill("#paste-name", name); await page.fill("#paste-text", text);
    await page.click("[data-act=paste-go]");
  };
  await paste("basura.pem", "-----BEGIN CERTIFICATE-----\nMIIBIjAN!!!basura\n-----END CERTIFICATE-----");
  await paste("include.conf", "include /etc/nginx/conf.d/*.conf;\nssl_protocols TLSv1.3; # ssl_ciphers RC4-SHA;\nssl_ciphers 'HIGH:!aNULL:!MD5';\nssl_ecdh_curve \"X25519MLKEM768:X25519\";");
  const row = async (n) => page.evaluate((n) => [...document.querySelectorAll("#view-inventario .cols-src.list-row")].find((r) => r.querySelector(".name").firstChild.textContent === n)?.children[3].textContent || "", n);
  const hasRow = async (n) => page.evaluate((n) => [...document.querySelectorAll("#view-inventario .cols-src.list-row")].some((r) => r.querySelector(".name").firstChild.textContent === n), n);
  check(/certificado|DER|ASN/i.test(await row("basura.pem")), "aviso PEM basura");
  check(/include/i.test(await row("include.conf")), "aviso de include en nginx");
  check(/HIGH|selector/i.test(await row("include.conf")), "aviso de selectores genéricos");
  check(!(await page.evaluate(() => [...document.querySelectorAll("#alg-list .list-row")].some((r) => r.querySelector(".name").firstChild.textContent.trim() === "RC4" && r.textContent.includes("include.conf")))), "comentario en línea ignorado");
  // Ficheros: vacío, DER binario, texto
  const empty = tmp("vacio.pem", "");
  const der = tmp("aleatorio.der", Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01, 0, 0, 0]));
  const huge = tmp("enorme-nginx.conf", "ssl_protocols TLSv1.2;\n" + "# relleno de configuración\n".repeat(150000) + "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n");
  const sshd = tmp("sshd_config", "KexAlgorithms -diffie-hellman-group1-sha1,+mlkem768x25519-sha256\nInclude /etc/ssh/sshd_config.d/*.conf\nCiphers=aes256-gcm@openssh.com # comentario\nMatch User copias\n  Ciphers aes128-ctr\n");
  const [fc] = await Promise.all([page.waitForEvent("filechooser"), page.click("[data-act=pick]")]);
  const t0 = Date.now();
  await fc.setFiles([empty, der, sshd, huge]);
  await page.waitForFunction(() => document.body.textContent.includes("enorme-nginx.conf"));
  check(Date.now() - t0 < 4000, `fichero de 4 MB analizado en ${Date.now() - t0} ms`);
  check(/AES-256-GCM|ECDHE/.test(await page.textContent("#alg-list")), "configuración enorme analizada");
  check(/vac/i.test(await row("vacio.pem")), "aviso fichero vacío");
  check(/certificado|DER|ASN/i.test(await row("aleatorio.der")) && !/undefined/.test(await row("aleatorio.der")), "DER aleatorio con error legible");
  check(/Include/i.test(await row("sshd_config")) && /Match/i.test(await row("sshd_config")), "avisos Include/Match en sshd");
  check(/Eliminados/.test(await row("sshd_config")), "KEX con '-' no se cuenta como habilitado");
  // Soltar ficheros (drag & drop)
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(["ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768;"], "soltado-nginx.conf"));
    document.querySelector("#drop").dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
  });
  await page.waitForTimeout(300);
  check(await hasRow("soltado-nginx.conf"), "drop de ficheros");
  // Quitar una fuente
  await page.click(`[aria-label="Quitar soltado-nginx.conf"]`);
  check(!(await hasRow("soltado-nginx.conf")), "quitar fuente");
  // Mejoras v0.2: indicador, certificados con cadena y extensiones
  check(/\d+\/100/.test(await page.textContent(".ready")), "indicador de preparación PQC");
  check(/Raíz autofirmada|Emisor cargado|Emisor no cargado/.test(await page.textContent("#view-inventario")), "estado de cadena de certificados");
  check(/SAN:|CA/.test(await page.textContent("#view-inventario")), "extensiones X.509 visibles");
  // Importar un CBOM
  const cbomFile = tmp("cbom-importado.cdx.json", JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "cryptographic-asset", name: "RSA-2048", cryptoProperties: { assetType: "algorithm" } }] }));
  const [fc2] = await Promise.all([page.waitForEvent("filechooser"), page.click("[data-act=pick]")]);
  await fc2.setFiles([cbomFile]);
  await page.waitForTimeout(200);
  check(/importado/.test(await row("cbom-importado.cdx.json")), "importar CBOM JSON");

  // Mosca
  await page.click(".tabs [data-view=mosca]");
  const n0 = (await page.$$("[data-asset]")).length;
  await page.click("[data-act=add-asset]");
  check((await page.$$("[data-asset]")).length === n0 + 1, "añadir activo");
  const last = "[data-asset]:last-child";
  const setXY = async (x, y) => { await page.fill(`${last} [data-f=x]`, x); await page.fill(`${last} [data-f=y]`, y); await page.waitForTimeout(500); return page.textContent(`${last} .asset-result`); };
  check(/holgura|exceso/.test(await setXY("0", "0")), "Mosca 0/0");
  const neg = await setXY("-5", "-3");
  check(!/-\d/.test(neg.replace(/holgura \d+/, "")), `Mosca negativos no se muestran: ${neg}`);
  const dec = await setXY("0.1", "0.2");
  check(!/0\.3000000/.test(dec), `Mosca decimales redondeados: ${dec}`);
  await setXY("1e9", "1");
  await noOverflow(page, "mosca valores enormes");
  check(/exceso/.test(await setXY("", "")) === false, "Mosca vacío no crítico");
  check(Number(await page.inputValue(`${last} [data-f=x]`)) >= 0, "Mosca X vacío no rompe el campo");
  await page.fill("#z-num", "0"); await page.waitForTimeout(450);
  check(Number(await page.inputValue("#z-num")) >= 1, "Z mínimo 1");
  await page.fill("#z-num", "500"); await page.waitForTimeout(450);
  check(Number(await page.inputValue("#z-num")) <= 50, "Z máximo 50");
  check((await page.$$(".sens-row")).length === n0 + 2, "tabla de sensibilidad de Z");
  await page.click(`${last} [data-act=rm-asset]`);
  check((await page.$$("[data-asset]")).length === n0, "eliminar activo");

  // Plan: estado persistente
  await page.click(".tabs [data-view=plan]");
  const sel = await page.$("[data-status]");
  check(!!sel, "plan con acciones");
  await sel.selectOption("en-curso");

  // Exportar y validar
  await page.click(".tabs [data-view=exportar]");
  check(await page.isVisible(".check.ok"), "estructura CBOM correcta");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("[data-act=download]")]);
  const p = await dl.path();
  const bom = JSON.parse((await import("node:fs")).readFileSync(p, "utf8"));
  check(bom.bomFormat === "CycloneDX" && bom.specVersion === "1.6" && bom.components.length > 20, "CBOM descargado");
  writeFileSync(join(tmpdir(), "cbom-e2e.json"), JSON.stringify(bom));
  const [md] = await Promise.all([page.waitForEvent("download"), page.click("[data-act=report-md]")]);
  const mdText = (await import("node:fs")).readFileSync(await md.path(), "utf8");
  check(/^# Informe/.test(mdText) && /\| Algoritmo \|/.test(mdText) && /En curso/.test(mdText), "informe Markdown con estados del plan");
  await page.evaluate(() => { window.print = () => { window.__printed = true; }; });
  await page.click("[data-act=report-print]");
  check(await page.evaluate(() => window.__printed && document.querySelector("#print-report table")), "informe imprimible");

  // Persistencia
  await page.reload(); await page.waitForSelector("#view-exportar.is-active h1");
  await page.click(".tabs [data-view=plan]");
  check(await page.evaluate(() => [...document.querySelectorAll("[data-status]")].some((s) => s.value === "en-curso")), "estado del plan persiste tras recargar");

  // localStorage corrupto en varias formas
  for (const bad of ["{no json", JSON.stringify({ sources: "x", assets: null, view: "nada", statuses: 5 }), JSON.stringify({ sources: [{ id: "1", name: "x.der", b64: "@@@" }, { foo: 1 }], assets: [{ id: "a", x: "abc" }], z: "NaN" })]) {
    await page.evaluate((b) => localStorage.setItem("cbom-pqc-lab:v1", b), bad);
    const errs = [];
    const h = (e) => errs.push(String(e));
    page.on("pageerror", h);
    await page.reload();
    await page.waitForTimeout(400);
    page.off("pageerror", h);
    check(errs.length === 0 && (await page.$(".view.is-active h1")), `localStorage corrupto (${bad.slice(0, 30)}): ${errs.join(" ")}`);
  }
  await page.evaluate(() => localStorage.clear());
  await page.reload();

  // Restablecer todo
  await page.click("[data-act=samples]");
  await page.click(".tabs [data-view=exportar]");
  page.once("dialog", (d) => d.accept());
  await page.click("[data-act=reset]");
  await page.waitForTimeout(200);
  check(await page.isVisible("#view-inventario .empty"), "restablecer vacía el inventario");

  // Teclado y ARIA
  check(await page.evaluate(() => [...document.querySelectorAll(".tabs .tab")].every((t) => t.getAttribute("aria-controls") && document.getElementById(t.getAttribute("aria-controls")))), "pestañas con aria-controls");
  await page.focus(".tabs [data-view=inventario]");
  await page.keyboard.press("ArrowRight");
  check(await page.evaluate(() => document.activeElement?.dataset.view === "mosca" && document.querySelector("#view-mosca.is-active")), "flechas mueven entre pestañas");
  check(await page.evaluate(() => [...document.querySelectorAll("button")].filter((b) => b.offsetParent).every((b) => (b.textContent.trim() || b.getAttribute("aria-label")))), "todos los botones con nombre accesible");
  check(await page.evaluate(() => [...document.querySelectorAll("input, select, textarea")].filter((b) => b.offsetParent && b.type !== "file").every((i) => i.labels?.length || i.getAttribute("aria-label"))), "todos los campos con etiqueta");
});

await browser.close();
console.log(`\n${passed} comprobaciones superadas, ${fails.length} fallos.`);
process.exit(fails.length ? 1 : 0);
