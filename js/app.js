import { SAMPLES } from "./samples.js";
import { parseSource, TYPES } from "./parsers.js";
import { buildInventory } from "./inventory.js";
import { CATEGORIES, ROLES } from "./classify.js";
import { ASSET_PRESETS, Z_PRESETS, evaluate, LEVELS } from "./mosca.js";
import { buildPlan, PRIORITIES } from "./plan.js";
import { buildCbom, checkCbom } from "./cbom.js";

const KEY = "cbom-pqc-lab:v1";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const YEAR = new Date().getFullYear();

const AUTOLINK = {
  hipoteca: ["nginx", "banca-online", "root-ca", "politica"],
  credito: ["s-client", "api-pagos", "nmap"],
  firma: ["api-pagos", "root-ca", "piloto"],
  sesion: ["nginx"],
  log: ["sshd", "nmap"],
};

function defaults() {
  return {
    theme: document.documentElement.dataset.theme, view: "inventario", sources: [], z: 10, zPreset: "central",
    assets: ASSET_PRESETS.map((a) => ({ ...a, links: null })), statuses: {}, filter: "all", query: "",
  };
}

let state = load();
let parsed = [];
let inv = { algorithms: [], certificates: [], protocols: [] };

function load() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY) || "null");
    return s ? { ...defaults(), ...s } : defaults();
  } catch { return defaults(); }
}
function save() {
  try { localStorage.setItem(KEY, JSON.stringify(state)); }
  catch { toast("No se pudo guardar: el almacenamiento local está lleno.", "triangle-alert"); }
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function bytesToB64(u) {
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}

function recompute() {
  parsed = state.sources.map((s) => ({
    ...s, parsed: parseSource(s.b64 ? { name: s.name, bytes: b64ToBytes(s.b64) } : { name: s.name, text: s.text }),
  }));
  inv = buildInventory(parsed);
}

function carriers() {
  return [
    ...inv.protocols.map((p) => ({ id: p.id, label: p.name.replace(/^[^·]+·\s*/, ""), kind: p.type.toUpperCase(), icon: p.type === "ssh" ? "terminal" : "network" })),
    ...inv.certificates.map((c) => ({ id: c.id, label: c.cn, kind: "Cert.", icon: "file-badge" })),
  ];
}
function linksOf(a) {
  if (Array.isArray(a.links)) return a.links;
  const kw = AUTOLINK[a.id] || [];
  const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return carriers().filter((c) => kw.some((k) => slug(c.id).includes(k))).map((c) => c.id);
}
function assetsResolved() { return state.assets.map((a) => ({ ...a, links: linksOf(a) })); }
function plan() { return buildPlan(inv, assetsResolved(), state.z); }

/* ---------- Iconos ---------- */
function icons(root = document) {
  window.lucide.createIcons({ attrs: { "stroke-width": 1.75, "aria-hidden": "true" }, root });
  $$(".draw", root).forEach((svg) => svg.querySelectorAll("path,circle,rect,line,polyline,polygon,ellipse").forEach((p) => p.setAttribute("pathLength", "1")));
}
const ic = (name, cls = "") => `<i data-lucide="${name}" class="${cls}"></i>`;

/* ---------- Navegación ---------- */
function show(view, animate = true) {
  state.view = view;
  save();
  $$(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.view === view)));
  $$(".view").forEach((v) => v.classList.toggle("is-active", v.id === `view-${view}`));
  render(view);
  const el = $(`#view-${view}`);
  if (animate && !reduced.matches) {
    el.classList.remove("is-entering");
    void el.offsetWidth;
    el.classList.add("is-entering");
    setTimeout(() => el.classList.remove("is-entering"), 900);
  }
}

function render(view = state.view) {
  ({ inventario: renderInventory, mosca: renderMosca, plan: renderPlan, exportar: renderExport })[view]();
}

let toastTimer;
function toast(msg, icon = "check") {
  const t = $("#toast");
  t.innerHTML = `${ic(icon)}<span>${esc(msg)}</span>`;
  icons(t);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2600);
}

const badge = (cat) => `<span class="badge c-${cat}">${esc(CATEGORIES[cat].short)}</span>`;

/* ---------- Inventario ---------- */
function renderInventory() {
  const el = $("#view-inventario");
  const counts = Object.fromEntries(Object.keys(CATEGORIES).map((k) => [k, inv.algorithms.filter((a) => a.category === k).length]));
  const total = inv.algorithms.length;
  const q = state.query.trim().toLowerCase();
  const rows = inv.algorithms
    .filter((a) => state.filter === "all" || a.category === state.filter)
    .filter((a) => !q || `${a.name} ${a.contexts.join(" ")} ${a.sources.join(" ")}`.toLowerCase().includes(q))
    .sort((a, b) => CATEGORIES[a.category].order - CATEGORIES[b.category].order || a.name.localeCompare(b.name));
  const order = ["vulnerable", "legacy", "hybrid", "pqc", "symmetric", "unknown"];

  el.innerHTML = `
  <div class="stagger">
    <div class="head">
      <span class="head-icon">${ic("scan-search", "draw")}</span>
      <div>
        <h1 id="h-inv">Inventario criptográfico</h1>
        <p class="lead">Carga certificados X.509, configuraciones de servidor o salidas de herramientas. Se analizan en este navegador y se clasifican frente a la amenaza cuántica.</p>
      </div>
    </div>

    <div class="drop" id="drop">
      <div>
        <h2>${ic("upload")}Suelta ficheros aquí</h2>
        <p class="muted" style="margin-top:6px">PEM o DER, nginx.conf, sshd_config, openssl.cnf, o texto de <code>openssl s_client</code> y <code>nmap --script ssl-enum-ciphers</code>.</p>
        <p class="note">${ic("info")}<span>Un navegador no puede abrir conexiones TLS ni escanear puertos. Para analizar un endpoint, ejecuta en tu equipo <code>openssl s_client -connect host:443</code> o <code>nmap --script ssl-enum-ciphers -p 443 host</code> y pega la salida.</span></p>
      </div>
      <div class="row-wrap">
        <button class="btn btn-primary" data-act="samples">${ic("folder-open", "ico ico-lift")}Cargar ejemplo</button>
        <button class="btn btn-secondary" data-act="pick">${ic("file-plus", "ico ico-pop")}Elegir ficheros</button>
        <button class="btn btn-tertiary" data-act="paste">${ic("clipboard-paste", "ico ico-drop")}Pegar texto</button>
      </div>
    </div>
    <div class="paste panel pad ${state.pasteOpen ? "is-open" : ""}" id="paste">
      <div style="display:grid;gap:12px">
        <label class="field">Nombre de la fuente<input type="text" id="paste-name" placeholder="p. ej. s_client-banca-movil.txt"></label>
        <label class="field">Contenido<textarea id="paste-text" placeholder="Pega aquí un certificado PEM, una configuración o la salida de una herramienta"></textarea></label>
        <div class="row-wrap"><button class="btn btn-primary" data-act="paste-go">${ic("scan-line", "ico ico-pop")}Analizar</button><button class="btn btn-tertiary" data-act="paste">Cancelar</button></div>
      </div>
    </div>

    ${total ? `
    <div class="section">
      <div class="section-head"><h2>Resumen</h2><span class="muted small tabular">${total} algoritmos · ${inv.certificates.length} certificados · ${inv.protocols.length} configuraciones de protocolo</span></div>
      <div class="panel pad">
        <div class="mix" role="img" aria-label="Distribución por clasificación">${order.filter((k) => counts[k]).map((k) => `<span class="fill c-${k}" style="flex-grow:${counts[k]}"></span>`).join("")}</div>
        <div class="legend">${order.filter((k) => counts[k]).map((k) => `<span class="legend-item c-${k}"><span class="dot fill"></span><b>${counts[k]}</b>${esc(CATEGORIES[k].label)}</span>`).join("")}</div>
      </div>
    </div>` : ""}

    <div class="section">
      <div class="section-head"><h2>Fuentes analizadas</h2>${state.sources.length ? `<button class="btn btn-tertiary btn-sm" data-act="clear-sources">${ic("trash-2", "ico ico-tilt")}Quitar todas</button>` : ""}</div>
      ${state.sources.length ? `<div class="list">
        <div class="list-head cols-src"><span>Fuente</span><span>Tipo</span><span>Hallazgos</span><span>Avisos</span><span></span></div>
        ${parsed.map((s) => `<div class="list-row cols-src">
          <span class="name wide">${esc(s.name)}${s.sample ? `<span class="sub">Dato de ejemplo · entidad ficticia</span>` : ""}</span>
          <span><span class="lbl">Tipo</span>${esc(s.parsed.typeLabel)}</span>
          <span class="tabular"><span class="lbl">Hallazgos</span>${s.parsed.algs.length + s.parsed.certs.length * 2}</span>
          <span class="muted small wide">${s.parsed.warnings.map(esc).join("<br>") || "—"}</span>
          <button class="btn btn-tertiary btn-sm btn-icon" data-act="rm" data-id="${esc(s.id)}" aria-label="Quitar ${esc(s.name)}">${ic("x")}</button>
        </div>`).join("")}
      </div>` : `<div class="list empty">${ic("inbox")}<p>Aún no hay fuentes. Carga el ejemplo del banco ficticio para ver la herramienta en marcha.</p></div>`}
    </div>

    ${total ? `
    <div class="section">
      <div class="section-head"><h2>Algoritmos</h2></div>
      <div class="filters" style="margin-bottom:14px">
        <button class="chip" data-filter="all" aria-pressed="${state.filter === "all"}">Todos</button>
        ${order.filter((k) => counts[k]).map((k) => `<button class="chip" data-filter="${k}" aria-pressed="${state.filter === k}"><span class="dot fill c-${k}"></span>${esc(CATEGORIES[k].short)}</button>`).join("")}
        <label class="search">${ic("search")}<input type="search" id="q" placeholder="Buscar algoritmo o fuente" value="${esc(state.query)}" aria-label="Buscar"></label>
      </div>
      <div class="list" id="alg-list">
        <div class="list-head cols-alg"><span>Algoritmo</span><span>Función</span><span>Clasificación</span><span>Dónde aparece</span></div>
        ${rows.length ? rows.map((a) => `<div class="list-row cols-alg">
          <span class="name wide">${esc(a.name)}<span class="sub">${esc(a.note)}</span></span>
          <span><span class="lbl">Función</span>${esc(ROLES[a.role] || "—")}</span>
          <span>${badge(a.category)}</span>
          <span class="muted small wide">${esc(a.contexts.slice(0, 3).join(" · "))}${a.contexts.length > 3 ? ` · +${a.contexts.length - 3}` : ""}<br>${esc(a.sources.join(", "))}</span>
        </div>`).join("") : `<div class="empty">Ningún algoritmo coincide con el filtro.</div>`}
      </div>
    </div>` : ""}

    ${inv.certificates.length ? `
    <div class="section">
      <h2>Certificados</h2>
      <div class="list">
        <div class="list-head cols-cert"><span>Sujeto</span><span>Clave</span><span>Firma</span><span>Validez</span><span>Estado</span></div>
        ${inv.certificates.map((c) => {
          const key = inv.algorithms.find((a) => a.id === c.keyRef);
          const days = Math.round((c.notAfter - Date.now()) / 864e5);
          return `<div class="list-row cols-cert">
            <span class="name wide">${esc(c.cn)}<span class="sub">${c.selfSigned ? "Autofirmado / raíz" : `Emisor: ${esc((c.issuer.match(/CN=([^,]+)/) || [])[1] || c.issuer)}`}</span></span>
            <span><span class="lbl">Clave</span>${esc(key?.name || c.keyAlg)}</span>
            <span><span class="lbl">Firma</span>${esc(c.sigAlg)}</span>
            <span class="tabular small"><span class="lbl">Validez</span>${c.notBefore.toISOString().slice(0, 10)} → ${c.notAfter.toISOString().slice(0, 10)}<span class="sub">${days >= 0 ? `${days} días restantes` : "Caducado"}</span></span>
            <span>${badge(key?.category || "unknown")}</span>
          </div>`;
        }).join("")}
      </div>
    </div>` : ""}

    ${inv.protocols.length ? `
    <div class="section">
      <h2>Protocolos</h2>
      <div class="list">
        <div class="list-head cols-proto"><span>Configuración</span><span>Versión</span><span>Intercambio de claves clásico</span><span>Estado</span></div>
        ${inv.protocols.map((p) => `<div class="list-row cols-proto">
          <span class="name wide">${esc(p.name)}</span>
          <span class="tabular"><span class="lbl">Versión</span>${esc(p.versions?.join(", ") || "—")}</span>
          <span class="muted small wide"><span class="lbl">Intercambio de claves clásico</span>${esc(p.classicalKex.join(", ") || "Ninguno")}</span>
          <span>${p.pqReady ? `<span class="badge c-hybrid">${ic("shield-check")}Ofrece PQC</span>` : `<span class="badge c-vulnerable">${ic("shield-alert")}Sin PQC</span>`}</span>
        </div>`).join("")}
      </div>
    </div>` : ""}
  </div>`;
  icons(el);
  bindDrop();
}

function addSources(list) {
  for (const s of list) {
    const existing = state.sources.findIndex((x) => x.name === s.name);
    const entry = { id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`, ...s };
    if (existing >= 0) state.sources[existing] = entry; else state.sources.push(entry);
  }
  recompute();
  save();
  renderInventory();
}

async function readFiles(files) {
  const out = [];
  for (const f of files) {
    if (f.size > 5 * 1024 * 1024) { toast(`${f.name} supera 5 MB y se ha omitido.`, "triangle-alert"); continue; }
    const buf = new Uint8Array(await f.arrayBuffer());
    const looksText = !buf.subarray(0, 512).some((b) => b === 0 || (b < 9));
    const isDer = !looksText || /\.(der|cer)$/i.test(f.name) && buf[0] === 0x30 && !looksText;
    if (isDer) out.push({ name: f.name, b64: bytesToB64(buf) });
    else out.push({ name: f.name, text: new TextDecoder().decode(buf) });
  }
  if (out.length) { addSources(out); toast(`${out.length} fuente${out.length > 1 ? "s" : ""} analizada${out.length > 1 ? "s" : ""} en local.`); }
}

function bindDrop() {
  const d = $("#drop");
  if (!d) return;
  ["dragenter", "dragover"].forEach((e) => d.addEventListener(e, (ev) => { ev.preventDefault(); d.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((e) => d.addEventListener(e, () => d.classList.remove("is-over")));
  d.addEventListener("drop", (ev) => { ev.preventDefault(); readFiles([...ev.dataTransfer.files]); });
}

/* ---------- Mosca ---------- */
function timeline(ev) {
  const span = Math.max(ev.sum, ev.Z, 1) + 2;
  const pct = (v) => `${(Math.min(v, span) / span) * 100}%`;
  const overStart = Math.max(ev.Z, ev.Y);
  const over = ev.sum > ev.Z ? `<span class="tl-seg tl-over" style="left:${pct(overStart)};width:calc(${pct(ev.sum)} - ${pct(overStart)})"></span>` : "";
  return `<div class="timeline" role="img" aria-label="Migración ${ev.Y} años, confidencialidad ${ev.X} años, amenaza en ${ev.Z} años">
      <div class="tl-track">
        <span class="tl-seg tl-y" style="left:0;width:${pct(ev.Y)}"></span>
        <span class="tl-seg tl-x" style="left:${pct(ev.Y)};width:calc(${pct(ev.sum)} - ${pct(ev.Y)})"></span>
        ${over}
      </div>
      <span class="tl-z" style="left:${pct(ev.Z)}"><span>Z · ${YEAR + ev.Z}</span></span>
    </div>
    <div class="tl-scale"><span>${YEAR}</span><span>${YEAR + Math.round(span / 2)}</span><span>${YEAR + span}</span></div>`;
}

function renderMosca() {
  const el = $("#view-mosca");
  const cs = carriers();
  const assets = assetsResolved();
  const evs = assets.map((a) => evaluate(a.x, a.y, state.z));
  const crit = evs.filter((e) => e.critical).length;
  el.innerHTML = `
  <div class="stagger">
    <div class="head">
      <span class="head-icon">${ic("hourglass", "draw")}</span>
      <div>
        <h1 id="h-mosca">Teorema de Mosca</h1>
        <p class="lead">Si el tiempo que un dato debe seguir siendo confidencial (X) más el tiempo que tardas en migrar (Y) supera el horizonte de amenaza cuántica (Z), ese dato ya es vulnerable hoy: puede capturarse ahora y descifrarse después.</p>
      </div>
    </div>

    <div class="panel pad">
      <div class="formula">
        <span class="formula-eq">X <i>+</i> Y <i>&gt;</i> Z</span>
        <span class="muted">${crit ? `<b style="color:var(--danger)">${crit} de ${assets.length}</b> activos con deuda criptográfica crítica` : "Ningún activo supera el horizonte con los supuestos actuales"}</span>
      </div>
      <div class="zctl">
        <div class="seg" role="group" aria-label="Escenario de horizonte cuántico">
          ${Z_PRESETS.map((p) => `<button data-z="${p.id}" aria-pressed="${state.zPreset === p.id}">${p.label} · ${p.z}</button>`).join("")}
        </div>
        <input type="range" id="z-range" min="1" max="30" step="1" value="${state.z}" aria-label="Horizonte Z en años">
        <label class="field" style="gap:2px">Z (años)<input type="number" id="z-num" min="1" max="50" value="${state.z}"></label>
      </div>
      <p class="note">${ic("triangle-alert")}<span>Z es un <b>supuesto</b>, no un hecho: nadie sabe cuándo existirá un ordenador cuántico capaz de romper RSA o ECC. Los escenarios son puntos de partida para debatir el riesgo; ajústalos a la postura de tu entidad. Valores de X e Y de ejemplo.</span></p>
    </div>

    <div class="section">
      <div class="section-head">
        <h2>Activos bancarios</h2>
        <div class="row-wrap">
          <button class="btn btn-secondary btn-sm" data-act="add-asset">${ic("plus", "ico ico-spin")}Añadir activo</button>
          <button class="btn btn-tertiary btn-sm" data-act="reset-assets">${ic("rotate-ccw", "ico ico-tilt")}Restaurar preajustes</button>
        </div>
      </div>
      <div class="list">
        ${assets.map((a, i) => {
          const ev = evs[i];
          return `<div class="asset" data-asset="${esc(a.id)}">
            <div class="asset-name">
              <label class="field">Activo<input type="text" data-f="name" value="${esc(a.name)}"></label>
              ${a.hint ? `<p class="asset-hint">${esc(a.hint)}</p>` : ""}
            </div>
            <label class="field">X · confidencial<input type="number" min="0" max="100" step="0.5" data-f="x" value="${a.x}"></label>
            <label class="field">Y · migración<input type="number" min="0" max="50" step="0.5" data-f="y" value="${a.y}"></label>
            <div class="asset-viz">
              <div class="asset-result">
                <span class="badge lv-${ev.level}" style="color:var(--c);background:var(--cs)">${ic(ev.critical ? "octagon-alert" : ev.level === "warning" ? "circle-alert" : "circle-check")}${esc(LEVELS[ev.level].label)}</span>
                <span class="small tabular muted">${ev.X} + ${ev.Y} = <b style="color:var(--text)">${ev.sum}</b> ${ev.critical ? "&gt;" : "≤"} ${ev.Z} · ${ev.margin > 0 ? `exceso ${ev.margin} años` : `holgura ${-ev.margin} años`}</span>
              </div>
              ${timeline(ev)}
              ${cs.length ? `<div class="links" aria-label="Por dónde viaja o se protege este activo">
                ${cs.map((c) => `<button class="chip" data-link="${esc(c.id)}" aria-pressed="${a.links.includes(c.id)}">${ic(c.icon)}${esc(c.label)}</button>`).join("")}
              </div>` : `<p class="asset-hint">Carga fuentes en Inventario para vincular este activo a su infraestructura.</p>`}
              ${a.custom ? `<div style="margin-top:10px"><button class="btn btn-danger btn-sm" data-act="rm-asset">${ic("trash-2")}Eliminar</button></div>` : ""}
            </div>
          </div>`;
        }).join("")}
      </div>
      <div class="tl-key"><span><i style="background:color-mix(in srgb, var(--text-2) 45%, transparent)"></i>Y · migración</span><span><i style="background:var(--accent)"></i>X · vida confidencial</span><span><i style="background:var(--danger)"></i>Expuesto tras Z</span></div>
    </div>
  </div>`;
  icons(el);
}

/* ---------- Plan ---------- */
function renderPlan() {
  const el = $("#view-plan");
  const items = plan();
  const by = (p) => items.filter((i) => i.prio === p);
  const st = (id) => state.statuses[id] || "pendiente";
  const done = items.filter((i) => st(i.id) === "migrado").length;
  el.innerHTML = `
  <div class="stagger">
    <div class="head">
      <span class="head-icon">${ic("route", "draw")}</span>
      <div>
        <h1 id="h-plan">Plan de transición PQC</h1>
        <p class="lead">Cada algoritmo vulnerable u obsoleto del inventario, con su destino en los estándares NIST y una prioridad derivada del Teorema de Mosca de los activos que protege.</p>
      </div>
    </div>
    ${items.length ? `
    <div class="panel kv">
      ${[1, 2, 3].map((p) => `<div><b>${by(p).length}</b><span>${esc(PRIORITIES[p].label)}</span></div>`).join("")}
      <div><b>${done}/${items.length}</b><span>Marcadas como migradas</span></div>
    </div>
    ${[1, 2, 3].filter((p) => by(p).length).map((p) => `
    <div class="prio">
      <div class="prio-head"><h2>${esc(PRIORITIES[p].label)}</h2><span class="muted small">${esc(PRIORITIES[p].hint)}</span></div>
      <div class="list">
        ${by(p).map((i) => `<div class="step">
          <div>
            <div class="name" style="font-weight:600">${esc(i.alg.name)}</div>
            <div class="row-wrap" style="margin-top:6px;gap:6px">${badge(i.alg.category)}${i.hndl ? `<span class="badge c-vulnerable">${ic("radar")}HNDL</span>` : ""}</div>
            <p class="sub" style="margin-top:6px">${esc(ROLES[i.alg.role] || "")}</p>
          </div>
          <div>
            <div class="arrow">${ic("arrow-right")}<div><span class="std">${esc(i.std)}</span><br><b>${esc(i.to)}</b><p class="sub">${esc(i.why)}</p>
            <p class="sub">${i.worst ? `Activo más expuesto: <b style="color:var(--text)">${esc(i.worst.name)}</b> (${i.worst.margin > 0 ? `exceso ${i.worst.margin} años` : `holgura ${-i.worst.margin} años`})` : "Sin activo vinculado en Mosca."}</p></div></div>
          </div>
          <label class="field">Estado
            <select data-status="${esc(i.id)}">
              ${[["pendiente", "Pendiente"], ["en-curso", "En curso"], ["migrado", "Migrado"], ["aceptado", "Riesgo aceptado"]].map(([v, l]) => `<option value="${v}" ${st(i.id) === v ? "selected" : ""}>${l}</option>`).join("")}
            </select>
          </label>
        </div>`).join("")}
      </div>
    </div>`).join("")}` : `<div class="list empty">${ic("route")}<p>No hay elementos que migrar. Carga fuentes en Inventario.</p></div>`}

    <div class="section">
      <h2>Marco de referencia</h2>
      <div class="panel pad reg">
        <div>
          <h3>${ic("binary")}Estándares NIST PQC</h3>
          <ul>
            <li><b>FIPS 203 · ML-KEM</b>: encapsulación de claves. Sustituye a ECDH/DH/RSA en el intercambio de claves; es lo que neutraliza HNDL.</li>
            <li><b>FIPS 204 · ML-DSA</b>: firma digital de propósito general (certificados, firma transaccional).</li>
            <li><b>FIPS 205 · SLH-DSA</b>: firma basada en hash, conservadora; útil para raíces y firmas de muy larga vida.</li>
          </ul>
        </div>
        <div>
          <h3>${ic("landmark")}DORA</h3>
          <p>El Reglamento (UE) 2022/2554 (DORA) exige a las entidades financieras un marco de gestión del riesgo TIC. Sus normas técnicas, el Reglamento Delegado (UE) 2024/1774, piden en su artículo 6 una política de cifrado y controles criptográficos basada en la clasificación de datos, con previsiones para actualizar la tecnología criptográfica según la evolución del criptoanálisis, y en su artículo 7 la gestión del ciclo de vida de las claves. Su considerando 9 menciona expresamente las amenazas derivadas de los avances cuánticos.</p>
        </div>
        <div>
          <h3>${ic("list-checks")}Cómo usar este plan</h3>
          <p>El inventario (CBOM) es la evidencia de qué criptografía está en uso; Mosca justifica la prioridad por clasificación de datos; los estados documentan avances, mitigaciones o riesgos aceptados. Es material de apoyo para el análisis, no un dictamen de cumplimiento.</p>
        </div>
      </div>
    </div>
  </div>`;
  icons(el);
}

/* ---------- Exportar ---------- */
let lastBom = null;
function renderExport() {
  const el = $("#view-exportar");
  const pl = plan();
  lastBom = buildCbom(inv, pl, { z: state.z, name: "Inventario criptográfico" });
  const errs = checkCbom(lastBom);
  const json = JSON.stringify(lastBom, null, 2);
  const by = (t) => lastBom.components.filter((c) => c.cryptoProperties.assetType === t).length;
  el.innerHTML = `
  <div class="stagger">
    <div class="head">
      <span class="head-icon">${ic("file-json", "draw")}</span>
      <div>
        <h1 id="h-exp">Exportar CBOM</h1>
        <p class="lead">Inventario en formato CycloneDX 1.6 con componentes <code>cryptographic-asset</code> y sus <code>cryptoProperties</code>: algoritmos, certificados, claves públicas y protocolos, con la clasificación y la prioridad del plan como propiedades.</p>
      </div>
    </div>
    <div class="panel kv">
      <div><b>${by("algorithm")}</b><span>Algoritmos</span></div>
      <div><b>${by("certificate")}</b><span>Certificados</span></div>
      <div><b>${by("related-crypto-material")}</b><span>Claves públicas</span></div>
      <div><b>${by("protocol")}</b><span>Protocolos</span></div>
    </div>
    <div class="section">
      <div class="section-head">
        ${errs.length ? `<span class="check bad">${ic("circle-x")}${errs.length} problemas de estructura</span>` : `<span class="check ok">${ic("circle-check")}Estructura CycloneDX 1.6 correcta</span>`}
        <div class="row-wrap">
          <button class="btn btn-primary" data-act="download" ${lastBom.components.length ? "" : "disabled"}>${ic("download", "ico ico-drop")}Descargar CBOM</button>
          <button class="btn btn-secondary" data-act="copy" ${lastBom.components.length ? "" : "disabled"}>${ic("copy", "ico ico-pop")}Copiar JSON</button>
        </div>
      </div>
      ${errs.length ? `<p class="muted small" style="margin-bottom:10px">${errs.map(esc).join("<br>")}</p>` : ""}
      <pre class="json" tabindex="0" aria-label="Vista previa del JSON">${esc(json)}</pre>
    </div>
    <div class="section">
      <h2>Privacidad y datos</h2>
      <div class="panel pad">
        <p class="note" style="margin-top:0">${ic("lock-keyhole")}<span>Todo se procesa en este navegador. No hay servidor, ni subidas, ni telemetría; la política de seguridad de la página bloquea cualquier conexión de red. El estado se guarda solo en el almacenamiento local de este navegador.</span></p>
        <div class="row-wrap" style="margin-top:16px">
          <button class="btn btn-danger" data-act="reset">${ic("rotate-ccw", "ico ico-tilt")}Restablecer todo</button>
          <span class="muted small">Borra fuentes, activos, estados y preferencias guardados.</span>
        </div>
      </div>
    </div>
  </div>`;
  icons(el);
}

/* ---------- Eventos ---------- */
document.addEventListener("click", async (e) => {
  const tab = e.target.closest(".tab[data-view]");
  if (tab) return show(tab.dataset.view);
  const f = e.target.closest("[data-filter]");
  if (f) { state.filter = f.dataset.filter; save(); return renderInventory(); }
  const z = e.target.closest("[data-z]");
  if (z) { const p = Z_PRESETS.find((x) => x.id === z.dataset.z); state.z = p.z; state.zPreset = p.id; save(); return renderMosca(); }
  const link = e.target.closest("[data-link]");
  if (link) {
    const id = link.closest("[data-asset]").dataset.asset;
    const a = state.assets.find((x) => x.id === id);
    const cur = linksOf(a);
    a.links = cur.includes(link.dataset.link) ? cur.filter((l) => l !== link.dataset.link) : [...cur, link.dataset.link];
    save();
    return renderMosca();
  }
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  if (act === "samples") {
    addSources(SAMPLES.map((s) => (s.binary ? { name: s.name, b64: s.b64, sample: true } : { name: s.name, text: s.text, sample: true })));
    toast("Ejemplo del Banco Ficticio Atlántida cargado.");
  } else if (act === "pick") $("#file").click();
  else if (act === "paste") { state.pasteOpen = !state.pasteOpen; $("#paste").classList.toggle("is-open", state.pasteOpen); if (state.pasteOpen) $("#paste-text").focus(); }
  else if (act === "paste-go") {
    const text = $("#paste-text").value;
    if (!text.trim()) return toast("Pega algún contenido antes de analizar.", "circle-alert");
    const name = $("#paste-name").value.trim() || `texto-pegado-${state.sources.length + 1}.txt`;
    state.pasteOpen = false;
    addSources([{ name, text }]);
    toast(`${name} analizado en local.`);
  } else if (act === "rm") { state.sources = state.sources.filter((s) => s.id !== b.dataset.id); recompute(); save(); renderInventory(); }
  else if (act === "clear-sources") { state.sources = []; recompute(); save(); renderInventory(); toast("Fuentes eliminadas."); }
  else if (act === "add-asset") {
    state.assets.push({ id: `a-${Date.now().toString(36)}`, name: "Nuevo activo", x: 10, y: 5, hint: "", custom: true, links: [] });
    save(); renderMosca();
    $$("#view-mosca [data-asset]").at(-1)?.querySelector("input")?.select();
  } else if (act === "rm-asset") { const id = b.closest("[data-asset]").dataset.asset; state.assets = state.assets.filter((a) => a.id !== id); save(); renderMosca(); }
  else if (act === "reset-assets") { state.assets = defaults().assets; state.z = 10; state.zPreset = "central"; save(); renderMosca(); toast("Preajustes restaurados."); }
  else if (act === "download") {
    const blob = new Blob([JSON.stringify(lastBom, null, 2)], { type: "application/vnd.cyclonedx+json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cbom-${new Date().toISOString().slice(0, 10)}.cdx.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast("CBOM descargado.", "download");
  } else if (act === "copy") {
    try { await navigator.clipboard.writeText(JSON.stringify(lastBom, null, 2)); toast("JSON copiado al portapapeles."); }
    catch { toast("El navegador no permite copiar aquí. Usa Descargar.", "circle-alert"); }
  } else if (act === "reset") {
    if (!confirm("¿Restablecer todo? Se borrarán las fuentes, los activos y los estados guardados en este navegador.")) return;
    localStorage.removeItem(KEY);
    state = defaults();
    recompute();
    show("inventario");
    toast("Datos locales borrados.");
  }
});

document.addEventListener("input", (e) => {
  const t = e.target;
  if (t.id === "q") {
    state.query = t.value; save();
    const pos = t.selectionStart;
    renderInventory();
    const n = $("#q"); n.focus(); n.setSelectionRange(pos, pos);
  } else if (t.id === "z-range" || t.id === "z-num") {
    const v = Math.max(1, Math.min(50, Number(t.value) || 1));
    state.z = v; state.zPreset = Z_PRESETS.find((p) => p.z === v)?.id || null; save();
    clearTimeout(t._r);
    if (t.id === "z-range") { renderMosca(); $("#z-range").focus(); }
    else t._r = setTimeout(() => { renderMosca(); const n = $("#z-num"); n.focus(); }, 350);
  } else if (t.dataset.f) {
    const a = state.assets.find((x) => x.id === t.closest("[data-asset]").dataset.asset);
    if (t.dataset.f === "name") { a.name = t.value; save(); return; }
    a[t.dataset.f] = Math.max(0, Number(t.value) || 0);
    save();
    clearTimeout(t._r);
    t._r = setTimeout(() => {
      const f = t.dataset.f, id = a.id;
      renderMosca();
      const n = $(`[data-asset="${CSS.escape(id)}"] [data-f="${f}"]`);
      n?.focus();
    }, 400);
  }
});

document.addEventListener("change", (e) => {
  const s = e.target.closest("[data-status]");
  if (s) { state.statuses[s.dataset.status] = s.value; save(); renderPlan(); }
});

$("#file").addEventListener("change", (e) => { readFiles([...e.target.files]); e.target.value = ""; });
document.addEventListener("paste", (e) => {
  if (state.view !== "inventario" || e.target.closest("input, textarea")) return;
  const text = e.clipboardData?.getData("text");
  if (text?.trim()) { addSources([{ name: `texto-pegado-${state.sources.length + 1}.txt`, text }]); toast("Texto pegado y analizado en local."); }
});

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  const btn = $("#theme");
  btn.innerHTML = ic(state.theme === "dark" ? "sun" : "moon", "ico ico-tilt");
  btn.setAttribute("aria-label", state.theme === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro");
  icons(btn);
}
$("#theme").addEventListener("click", () => { state.theme = state.theme === "dark" ? "light" : "dark"; save(); applyTheme(); });

recompute();
applyTheme();
icons();
show(state.view || "inventario", true);
