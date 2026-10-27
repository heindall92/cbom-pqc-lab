// Pruebas de v0.3: certificados PQC y compuestos, sesión, comparación, include e importación completa de CBOM.
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const { parseSource, resolveIncludes, mergeIncludes, matchInclude, importCbom } = await import("../js/parsers.js");
const { OIDS } = await import("../js/x509.js");
const { classify } = await import("../js/classify.js");
const { buildInventory } = await import("../js/inventory.js");
const { buildPlan } = await import("../js/plan.js");
const { buildCbom } = await import("../js/cbom.js");
const { certIssues, buildMarkdown, readiness } = await import("../js/report.js");
const { ASSET_PRESETS } = await import("../js/mosca.js");
const { buildSession, validateSession, snapshotInventory, reviveInventory } = await import("../js/session.js");
const { diffInventories, diffMarkdown } = await import("../js/diff.js");
const { SAMPLES } = await import("../js/samples.js");

let ok = 0; const bad = [];
const t = (cond, msg) => (cond ? ok++ : bad.push(msg));
const parseSample = (s) => parseSource(s.binary ? { name: s.name, bytes: Uint8Array.from(Buffer.from(s.b64, "base64")) } : { name: s.name, text: s.text });
const src = SAMPLES.map((s) => ({ name: s.name, parsed: parseSample(s) }));
const inv = buildInventory(src);
const cert = (cn) => inv.certificates.find((c) => c.cn === cn);
const alg = (id) => inv.algorithms.find((a) => a.id === id);

// Tabla de OID (NIST CSOR y draft-ietf-lamps-pq-composite-sigs-19)
const S = "2.16.840.1.101.3.4.3.";
t(OIDS[`${S}17`].name === "ML-DSA-44" && OIDS[`${S}18`].name === "ML-DSA-65" && OIDS[`${S}19`].name === "ML-DSA-87", "OID ML-DSA 44/65/87");
t(OIDS[`${S}20`].name === "SLH-DSA-SHA2-128s" && OIDS[`${S}25`].name === "SLH-DSA-SHA2-256f" && OIDS[`${S}31`].name === "SLH-DSA-SHAKE-256f", "OID SLH-DSA 12 variantes");
t(OIDS[`${S}32`].name === "HashML-DSA-44-SHA512" && OIDS[`${S}46`].name === "HashSLH-DSA-SHAKE-256f-SHAKE256", "OID variantes con prehash");
t(["512", "768", "1024"].every((n, i) => OIDS[`2.16.840.1.101.3.4.4.${i + 1}`].name === `ML-KEM-${n}`), "OID ML-KEM");
const comp = Array.from({ length: 18 }, (_, i) => OIDS[`1.3.6.1.5.5.7.6.${37 + i}`]);
t(comp.every((c) => c && c.provisional && c.family === "composite" && c.components.length === 2), "18 OID compuestos provisionales");
t(OIDS["1.3.6.1.5.5.7.6.45"].name === "MLDSA65-ECDSA-P256-SHA512", "OID .45 = MLDSA65-ECDSA-P256-SHA512");
t(!Object.values(OIDS).some((o) => !o.provisional && o.family === "composite"), "ningún compuesto sin marca provisional");
for (const o of Object.values(OIDS).filter((o) => ["ML-DSA", "SLH-DSA", "ML-KEM"].includes(o.family))) t(classify(o.name).category === "pqc", `${o.name} clasificado PQC`);
for (const c of comp) t(classify(c.name).category === "hybrid" && classify(c.name).name === c.name, `${c.name} clasificado híbrido`);

// Certificados de ejemplo
const ml = cert("piloto-pqc.atlantida.example");
t(ml && ml.keyAlg === "ML-DSA-65" && ml.sigAlg === "ML-DSA-65" && ml.pubBytes === 1952, "certificado ML-DSA-65 (clave de 1952 bytes)");
const slh = cert("firma-archivo.atlantida.example");
t(slh && slh.keyAlg === "SLH-DSA-SHA2-128s" && alg(slh.keyRef).category === "pqc", "certificado SLH-DSA-SHA2-128s");
const kem = cert("kem-pagos.atlantida.example");
t(kem && kem.keyAlg === "ML-KEM-768" && kem.sigAlg === "ML-DSA-65" && alg(kem.keyRef).role === "kex" && kem.pubBytes === 1184, "certificado con clave ML-KEM-768");
const cp = cert("pasarela-hibrida.atlantida.example");
t(cp && cp.keyAlg === "MLDSA65-ECDSA-P256-SHA512" && cp.provisional && cp.components.join() === "ML-DSA-65,ECDSA-P256", "certificado compuesto reconocido");
t(cp && alg(cp.keyRef).category === "hybrid" && cp.pubBytes === 1952 + 65, "compuesto: híbrido y clave mldsaPK||ecPK");
t(certIssues(cp).includes("OID provisional (borrador IETF)"), "compuesto: aviso de OID provisional");
t(!certIssues(ml).some((x) => /provisional/.test(x)), "ML-DSA definitivo sin aviso provisional");

// SAN: solo el ejemplo deliberadamente defectuoso dispara el aviso
const noSan = inv.certificates.filter((c) => certIssues(c).includes("Sin SubjectAltName")).map((c) => c.cn);
t(noSan.length === 1 && noSan[0] === "intranet-legada.atlantida.example", `aviso SAN solo en el defectuoso: ${noSan.join(", ")}`);
t(certIssues(cert("intranet-legada.atlantida.example")).some((x) => /SHA1/.test(x)), "defectuoso: firma SHA-1 avisada");
t(inv.certificates.filter((c) => c.ext.ca === false).every((c) => c.cn === "intranet-legada.atlantida.example" || c.ext.san.length), "certificados de entidad final buenos con SAN");
t(readiness(inv).parts.find((p) => p.id === "certpqc").ok === 4, "indicador: 4 certificados con clave PQC o híbrida");

// include: nginx y sshd
const ngx = "server {\n  include /etc/nginx/conf.d/20-*.conf;\n  include snippets/tls-pqc.conf; # tls\n  ssl_protocols TLSv1.3;\n}";
const files = [{ name: "tls-pqc.conf", text: "ssl_ecdh_curve X25519MLKEM768:X25519;" }, { name: "20-ciphers.conf", text: "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;" }, { name: "otro.txt", text: "x" }];
const r1 = resolveIncludes("nginx", ngx, files);
t(r1.merged.includes("tls-pqc.conf") && r1.merged.includes("20-ciphers.conf") && !r1.merged.includes("otro.txt"), "include nginx: glob y nombre exacto");
const p1 = parseSource({ name: "nginx.conf", text: ngx, includes: files });
t(p1.algs.some((a) => a.raw === "X25519MLKEM768") && p1.algs.some((a) => a.raw === "AES-256-GCM"), "include nginx: algoritmos del fichero incluido inventariados");
t(/Include fusionado/.test(p1.warnings.join()) && !/sin fichero/.test(p1.warnings.join()), "include nginx: aviso de fusión, sin aviso de ausencia");
const p2 = parseSource({ name: "nginx.conf", text: ngx, includes: [files[0]] });
t(/sin fichero \(\/etc\/nginx\/conf\.d\/20-\*\.conf\)/.test(p2.warnings.join()), "include nginx: se mantiene el aviso del que falta");
t(p2.missingIncludes.length === 1 && p2.merged.length === 1, "include nginx: fusionados y ausentes por separado");
const p3 = parseSource({ name: "sshd_config", text: "Include /etc/ssh/sshd_config.d/*.conf\nCiphers aes256-gcm@openssh.com", includes: [{ name: "50-pqc.conf", text: "KexAlgorithms mlkem768x25519-sha256" }] });
t(p3.algs.some((a) => a.raw === "mlkem768x25519-sha256" && a.ctx === "SSH KexAlgorithms") && !/sin fichero/.test(p3.warnings.join()), "include sshd fusionado");
const loop = resolveIncludes("nginx", "include a.conf;", [{ name: "a.conf", text: "include a.conf; ssl_protocols TLSv1.3;" }]);
t(loop.merged.length === 1, "include recursivo no entra en bucle");
t(matchInclude("C:\\nginx\\conf\\ssl.conf", [{ name: "SSL.conf" }]).length === 1, "include: rutas Windows y mayúsculas");
const mg = mergeIncludes([{ name: "nginx.conf", text: ngx }, ...files]);
t(mg.list.length === 2 && mg.used.length === 2 && mg.list[0].includes.length === 2, "lote: los incluidos se fusionan y no se duplican como fuentes");
t(mergeIncludes([{ name: "nginx.conf", text: "ssl_protocols TLSv1.3;" }, files[0]]).list.length === 2, "lote sin include: fuentes separadas");

// Importación completa de CBOM: algoritmos, certificados y protocolos
const assets = ASSET_PRESETS.map((a) => ({ ...a, links: inv.protocols.map((p) => p.id) }));
const plan = buildPlan(inv, assets, 10);
const bom = JSON.parse(JSON.stringify(buildCbom(inv, plan, { z: 10 })));
const imp = parseSource({ name: "previo.cdx.json", text: JSON.stringify(bom) });
t(imp.type === "cbom" && imp.certs.length === inv.certificates.length && imp.protocols.length === inv.protocols.length, `CBOM: ${imp.certs.length} certificados y ${imp.protocols.length} protocolos restaurados`);
const inv2 = buildInventory([{ name: "previo.cdx.json", parsed: imp }]);
const names = (i) => i.algorithms.map((a) => `${a.name}:${a.category}`).sort().join();
t(names(inv2) === names(inv), "CBOM: mismos algoritmos y clasificación tras ida y vuelta");
t(inv2.certificates.every((c) => inv.certificates.some((o) => o.cn === c.cn && o.notAfter.getTime() === c.notAfter.getTime() && alg(o.keyRef).name === inv2.algorithms.find((a) => a.id === c.keyRef).name)), "CBOM: certificados con clave, sujeto y fechas");
t(inv2.protocols.map((p) => `${p.name}:${p.pqReady}`).sort().join() === inv.protocols.map((p) => `${p.name}:${p.pqReady}`).sort().join(), "CBOM: protocolos con su estado PQC");
t(readiness(inv2).score === readiness(inv).score, "CBOM: mismo indicador de preparación tras ida y vuelta");
t(inv2.certificates.find((c) => c.cn === "pasarela-hibrida.atlantida.example")?.provisional, "CBOM: compuesto sigue marcado provisional");
t(/3 ?|certificados/.test(imp.warnings.join()) && /protocolos/.test(imp.warnings.join()), "CBOM: aviso con recuento");
const ssh = inv2.protocols.find((p) => p.type === "ssh");
t(ssh && ssh.kex.includes("mlkem768x25519-sha256") && ssh.macs.length > 0, "CBOM: SSH con KEX y MAC por función");
let threw = false; try { importCbom({ bomFormat: "CycloneDX", components: 3 }); } catch { threw = true; }
t(threw, "CBOM sin componentes rechazado");
const partial = importCbom({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "cryptographic-asset", name: "x", "bom-ref": "c", cryptoProperties: { assetType: "certificate", certificateProperties: { notValidBefore: "nope" } } }] });
t(partial.certs.length === 0 && /sin fechas/.test(partial.warnings.join()), "CBOM: certificado sin fechas omitido con aviso");

// Sesión
const state = { sources: SAMPLES.slice(0, 3).map((s) => (s.binary ? { name: s.name, b64: s.b64, sample: true } : { name: s.name, text: s.text, sample: true })), z: 12, zPreset: null, assets: ASSET_PRESETS, statuses: { "alg-rsa-2048": "en-curso" } };
const ses = JSON.parse(JSON.stringify(buildSession({ state, inv, appVersion: "0.3.0" })));
t(ses.schema === "cbom-pqc-lab/session" && ses.version === 1 && ses.app.version === "0.3.0", "sesión con esquema y versión");
const v = validateSession(JSON.stringify(ses));
t(v.ok && v.session.sources.length === 3 && v.session.mosca.z === 12 && v.session.plan.statuses["alg-rsa-2048"] === "en-curso", "sesión válida e íntegra");
t(v.session.inventory.algorithms.length === inv.algorithms.length && v.session.inventory.certificates.length === inv.certificates.length, "sesión incluye el inventario analizado");
const err = (x) => validateSession(x).errors.join(" ");
t(/JSON válido/.test(err("{no")), "sesión: JSON roto");
t(/CBOM/.test(err(bom)), "sesión: un CBOM se distingue de una sesión");
t(/schema/.test(err({ foo: 1 })), "sesión: falta schema");
t(/más reciente/.test(err({ ...ses, version: 9 })), "sesión: versión futura");
t(/Z debe/.test(err({ ...ses, mosca: { ...ses.mosca, z: 99 } })), "sesión: Z fuera de rango");
t(/Estado del plan/.test(err({ ...ses, plan: { statuses: { a: "hecho" } } })), "sesión: estado no válido");
t(/Fuente n\.º 1/.test(err({ ...ses, sources: [{ name: 1 }] })), "sesión: fuente sin contenido");
t(/Base64/.test(err({ ...ses, sources: [{ name: "a.der", b64: "@@" }] })), "sesión: Base64 inválido");
t(/category/.test(err({ ...ses, inventory: { ...ses.inventory, algorithms: [{ name: "x", category: "rara" }] } })), "sesión: categoría desconocida");
t(validateSession({ schema: "cbom-pqc-lab/session", version: 1, sources: [] }).ok, "sesión mínima válida");

// Comparación
const prevInv = buildInventory(src.filter((s) => !/composite|kem|slh|politica/.test(s.name)));
const d = diffInventories(reviveInventory(snapshotInventory(prevInv)), reviveInventory(snapshotInventory(inv)));
t(d.added.some((a) => a.name === "MLDSA65-ECDSA-P256-SHA512") && d.added.some((a) => a.name === "ML-KEM-768"), "comparación: algoritmos añadidos");
t(d.removed.length === 0 && d.certs.added.includes("pasarela-hibrida.atlantida.example"), "comparación: certificados añadidos");
t(d.readiness.delta === readiness(inv).score - readiness(prevInv).score && d.readiness.delta > 0, `comparación: delta del indicador ${d.readiness.delta}`);
t(d.vulnerable.delta === inv.algorithms.filter((a) => a.category === "vulnerable").length - prevInv.algorithms.filter((a) => a.category === "vulnerable").length, "comparación: delta de vulnerables");
const back = diffInventories(inv, prevInv);
t(back.removed.length === d.added.length && back.readiness.delta === -d.readiness.delta, "comparación simétrica");
const fake = { algorithms: [{ name: "X", category: "vulnerable" }], certificates: [], protocols: [] };
const ch = diffInventories(fake, { algorithms: [{ name: "x", category: "legacy" }], certificates: [], protocols: [] });
t(ch.changed.length === 1 && ch.changed[0].from === "vulnerable" && ch.changed[0].to === "legacy", "comparación: reclasificados");
const md = buildMarkdown({ inv, plan, assets, z: 10, diff: d, diffLabel: "sesion-previa.json" });
t(/## Comparación con sesion-previa\.json/.test(md) && /Indicador de preparación PQC: \d+ → \d+ \(\+\d+\)/.test(md), "informe con comparación");
t(!/## Comparación/.test(buildMarkdown({ inv, plan, assets, z: 10 })), "informe sin comparación si no hay referencia");
t(/ninguno/.test(diffMarkdown(diffInventories(inv, inv))), "comparación idéntica sin cambios");

console.log(`${ok} pruebas unitarias v0.3 superadas, ${bad.length} fallos.`);
bad.forEach((b) => console.error("FALLO:", b));
process.exit(bad.length ? 1 : 0);
