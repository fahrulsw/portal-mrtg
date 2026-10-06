require("dotenv").config();
const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const db = require("./db");

// Kolom info layanan (nama kolom -> panjang maksimal). Migrasi aman: hanya menambah kolom yang belum ada.
const SVC_COLS = { service_type: 60, pks_no: 60, vlan: 40, ip_ptp: 100, location: 100 };
const SVC_KEYS = Object.keys(SVC_COLS);
{
  const have = new Set(db.prepare("PRAGMA table_info(services)").all().map((c) => c.name));
  for (const k of SVC_KEYS)
    if (!have.has(k)) db.prepare(`ALTER TABLE services ADD COLUMN ${k} TEXT NOT NULL DEFAULT ''`).run();
}

for (const k of ["SESSION_SECRET", "LNMS_URL", "LNMS_TOKEN"]) {
  if (!process.env[k]) { console.error(`Variabel ${k} belum diisi di .env`); process.exit(1); }
}

const app = express();
const behindProxy = process.env.BEHIND_PROXY === "1";
if (behindProxy) app.set("trust proxy", 1);

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: behindProxy, maxAge: 8 * 3600 * 1000 },
}));

const LNMS = process.env.LNMS_URL.replace(/\/$/, "");
const HEAD = { "X-Auth-Token": process.env.LNMS_TOKEN };
const RANGE = { day: 86400, week: 604800, month: 2592000, year: 31536000 };

// Cache grafik di memori (5 menit, selaras dengan interval polling SNMP)
const cache = new Map();
const TTL = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cache) if (now - v.t > TTL) cache.delete(k);
}, 60 * 1000).unref();

const normUser = (u) => String(u || "").trim().toLowerCase();
const USER_RE = /^[a-z0-9._@-]{3,64}$/;

const requireLogin = (req, res, next) => {
  const id = req.session.customerId;
  const me = id && db.prepare("SELECT active FROM customers WHERE id = ?").get(id);
  if (!me || !me.active) return res.status(401).json({ error: "Please sign in first" });
  next();
};

const isAdmin = (req) => {
  const id = req.session.customerId;
  const me = id && db.prepare("SELECT is_admin, active FROM customers WHERE id = ?").get(id);
  return !!(me && me.is_admin && me.active);
};
const requireAdmin = (req, res, next) =>
  isAdmin(req) ? next() : res.status(403).json({ error: "Admins only" });

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: "Too many attempts. Try again in 15 minutes." },
});

// ---------- Auth ----------
app.post("/api/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "Username and password are required" });
  const c = db.prepare("SELECT * FROM customers WHERE username = ?").get(normUser(username));
  if (!c || !c.active || !bcrypt.compareSync(password, c.password_hash))
    return res.status(401).json({ error: "Incorrect username or password" });
  req.session.regenerate(() => {
    req.session.customerId = c.id;
    res.json({ ok: true, admin: !!c.is_admin });
  });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/me", requireLogin, (req, res) => {
  const c = db.prepare("SELECT name, username, is_admin FROM customers WHERE id = ?").get(req.session.customerId);
  res.json({ name: c.name, username: c.username, admin: !!c.is_admin });
});

// ---------- Ganti password sendiri ----------
const passLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: "Too many attempts. Try again in 15 minutes." },
});
app.post("/api/me/password", requireLogin, passLimiter, (req, res) => {
  const cur = req.body?.current, next = req.body?.next;
  if (typeof cur !== "string" || typeof next !== "string")
    return res.status(400).json({ error: "Current and new password are required" });
  if (next.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (Buffer.byteLength(next) > 72) return res.status(400).json({ error: "Password must be at most 72 characters" });
  const c = db.prepare("SELECT password_hash FROM customers WHERE id = ?").get(req.session.customerId);
  // 400, bukan 401, supaya frontend tidak mengira sesi habis
  if (!c || !bcrypt.compareSync(cur, c.password_hash))
    return res.status(400).json({ error: "Current password is incorrect" });
  if (cur === next) return res.status(400).json({ error: "New password must be different" });
  db.prepare("UPDATE customers SET password_hash = ? WHERE id = ?")
    .run(bcrypt.hashSync(next, 12), req.session.customerId);
  res.json({ ok: true });
});

// ---------- Layanan milik pelanggan ----------
app.get("/api/services", requireLogin, (req, res) => {
  const rows = db.prepare(`SELECT id, label, ${SVC_KEYS.join(", ")} FROM services WHERE customer_id = ?`)
                 .all(req.session.customerId);
  res.json(rows);
});

// ---------- Grafik traffic (proxy ke LibreNMS) ----------
// Mencoba beberapa bentuk endpoint, karena berbeda antar versi LibreNMS.
// Semua kegagalan dicatat di log terminal supaya mudah dilacak.
async function lnmsGet(path, qs) {
  const url = `${LNMS}${path}${qs ? "?" + qs : ""}`;
  try {
    const r = await fetch(url, { headers: HEAD, signal: AbortSignal.timeout(10000) });
    return { r, url };
  } catch (err) {
    console.error(`[LNMS] gagal konek ${url}: ${err.cause?.code || err.message}`);
    return { r: null, url };
  }
}

// Mengingat path grafik yang berhasil per port, supaya tidak mencoba bentuk yang salah lagi.
const pathCache = new Map();

async function candidatePaths(portId) {
  if (pathCache.has(portId)) return [pathCache.get(portId)];

  const paths = [];
  // Bentuk umum: /devices/{device_id}/ports/{ifName}/port_bits
  const info = await lnmsGet(`/ports/${portId}`);
  if (info.r?.ok) {
    try {
      const p = (await info.r.json()).port?.[0];
      if (p?.device_id && p?.ifName) {
        paths.push(`/devices/${p.device_id}/ports/${encodeURIComponent(p.ifName)}/port_bits`);
      }
    } catch { /* abaikan */ }
  } else if (info.r) {
    console.error(`[LNMS] ${info.r.status} untuk ${info.url}: ${(await info.r.text()).slice(0, 200)}`);
  }
  // Cadangan untuk versi yang punya route berbasis port_id
  paths.push(`/ports/${portId}/port_bits`);
  return paths;
}

async function fetchGraph(portId, qs) {
  for (const path of await candidatePaths(portId)) {
    const { r, url } = await lnmsGet(path, qs);
    if (!r) continue;
    const type = r.headers.get("content-type") || "";
    if (r.ok && type.startsWith("image/")) {
      pathCache.set(portId, path);
      return { buf: Buffer.from(await r.arrayBuffer()), type };
    }
    console.error(`[LNMS] ${r.status} (${type}) untuk ${url}: ${(await r.text()).slice(0, 200)}`);
  }
  return null;
}

app.get("/graph/:id/:period.png", requireLogin, async (req, res) => {
  const { id, period } = req.params;
  if (!RANGE[period]) return res.sendStatus(404);

  // Cek kepemilikan: ini kunci keamanannya
  const svc = db.prepare("SELECT * FROM services WHERE id = ? AND customer_id = ?")
                .get(id, req.session.customerId);
  if (!svc) return res.sendStatus(404);

  const small = req.query.s === "sm";
  const key = `${svc.lnms_port_id}:${period}:${small ? "s" : "l"}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.t < TTL) {
    return res.type(hit.type).set("Cache-Control", "private, max-age=300").send(hit.buf);
  }

  const now = Math.floor(Date.now() / 1000);
  const qs = new URLSearchParams({
    from: now - RANGE[period], to: now,
    width: small ? 400 : 700, height: small ? 140 : 250,
  }).toString();

  const g = await fetchGraph(svc.lnms_port_id, qs);
  if (!g) return res.sendStatus(502);
  cache.set(key, { buf: g.buf, type: g.type, t: Date.now() });
  res.type(g.type).set("Cache-Control", "private, max-age=300").send(g.buf);
});

// ---------- Data traffic JSON (dari agent di server LibreNMS) ----------
const AGENT = (process.env.AGENT_URL || "").replace(/\/$/, "");
const trafficCache = new Map();

app.get("/api/traffic/:id/:period", requireLogin, async (req, res) => {
  const { id, period } = req.params;
  if (!RANGE[period]) return res.sendStatus(404);
  if (!AGENT || !process.env.AGENT_TOKEN) return res.status(503).json({ error: "Agent is not configured" });

  // cek kepemilikan, sama seperti route grafik PNG
  const svc = db.prepare("SELECT * FROM services WHERE id = ? AND customer_id = ?")
                .get(intId(id), req.session.customerId);
  if (!svc) return res.sendStatus(404);

  const key = `${svc.lnms_port_id}:${period}`;
  const hit = trafficCache.get(key);
  if (hit && Date.now() - hit.t < TTL) return res.set("Cache-Control", "private, max-age=300").json(hit.data);

  try {
    const r = await fetch(`${AGENT}/traffic?port_id=${svc.lnms_port_id}&range=${period}`, {
      headers: { "X-Agent-Token": process.env.AGENT_TOKEN },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) { console.error(`[AGENT] ${r.status} untuk port ${svc.lnms_port_id}`); return res.sendStatus(502); }
    const x = await r.json();
    const data = {
      start: x.meta.start, step: x.meta.step,
      in: x.data.map((d) => d[0]), out: x.data.map((d) => d[1]),
    };
    trafficCache.set(key, { data, t: Date.now() });
    res.set("Cache-Control", "private, max-age=300").json(data);
  } catch (e) {
    console.error("[AGENT] gagal:", e.cause?.code || e.message);
    res.sendStatus(502);
  }
});

// ---------- Admin ----------
const intId = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const isConstraint = (e) => String(e.code || "").startsWith("SQLITE_CONSTRAINT");
const findCustomer = (id) => db.prepare("SELECT * FROM customers WHERE id = ? AND is_admin = 0").get(id);

app.get("/api/admin/customers", requireAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT c.id, c.name, c.username, c.active,
           (SELECT COUNT(*) FROM services s WHERE s.customer_id = c.id) AS services
    FROM customers c WHERE c.is_admin = 0 ORDER BY c.name COLLATE NOCASE`).all());
});

app.post("/api/admin/customers", requireAdmin, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const username = normUser(req.body?.username);
  const password = String(req.body?.password || "");
  if (!name) return res.status(400).json({ error: "Name is required" });
  if (!USER_RE.test(username))
    return res.status(400).json({ error: "Username must be 3-64 characters: lowercase letters, digits, dot, underscore, hyphen, or @" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  try {
    const r = db.prepare("INSERT INTO customers (name, username, password_hash) VALUES (?, ?, ?)")
                .run(name, username, bcrypt.hashSync(password, 12));
    res.status(201).json({ id: r.lastInsertRowid });
  } catch (e) {
    if (isConstraint(e)) return res.status(409).json({ error: "Username is already taken" });
    throw e;
  }
});

app.patch("/api/admin/customers/:id", requireAdmin, (req, res) => {
  const c = findCustomer(intId(req.params.id));
  if (!c) return res.sendStatus(404);
  const { name, password, active } = req.body || {};
  if (name !== undefined) {
    if (!String(name).trim()) return res.status(400).json({ error: "Name is required" });
    db.prepare("UPDATE customers SET name = ? WHERE id = ?").run(String(name).trim(), c.id);
  }
  if (password !== undefined) {
    if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    db.prepare("UPDATE customers SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(String(password), 12), c.id);
  }
  if (active !== undefined) db.prepare("UPDATE customers SET active = ? WHERE id = ?").run(active ? 1 : 0, c.id);
  res.json({ ok: true });
});

app.delete("/api/admin/customers/:id", requireAdmin, (req, res) => {
  const c = findCustomer(intId(req.params.id));
  if (!c) return res.sendStatus(404);
  db.transaction(() => {
    db.prepare("DELETE FROM services WHERE customer_id = ?").run(c.id);
    db.prepare("DELETE FROM customers WHERE id = ?").run(c.id);
  })();
  res.json({ ok: true });
});

app.get("/api/admin/customers/:id/services", requireAdmin, (req, res) => {
  const c = findCustomer(intId(req.params.id));
  if (!c) return res.sendStatus(404);
  res.json(db.prepare(`SELECT id, label, lnms_port_id, ${SVC_KEYS.join(", ")} FROM services WHERE customer_id = ? ORDER BY id`).all(c.id));
});

function serviceInput(body) {
  const label = String(body?.label || "").trim();
  const port = intId(body?.lnms_port_id);
  if (!label || label.length > 120) return { error: "Label is required (max. 120 characters)" };
  if (!port) return { error: "Port ID must be a number" };
  const fields = {};
  for (const [k, max] of Object.entries(SVC_COLS)) {
    const val = String(body?.[k] || "").trim();
    if (val.length > max) return { error: `${k.replace("_", " ")} is too long (max. ${max} characters)` };
    fields[k] = val;
  }
  return { label, port, fields };
}

app.post("/api/admin/customers/:id/services", requireAdmin, (req, res) => {
  const c = findCustomer(intId(req.params.id));
  if (!c) return res.sendStatus(404);
  const v = serviceInput(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const r = db.prepare(`INSERT INTO services (customer_id, label, lnms_port_id, ${SVC_KEYS.join(", ")}) VALUES (?, ?, ?, ${SVC_KEYS.map(() => "?").join(", ")})`)
    .run(c.id, v.label, v.port, ...SVC_KEYS.map((k) => v.fields[k]));
  res.status(201).json({ id: r.lastInsertRowid });
});

app.patch("/api/admin/services/:id", requireAdmin, (req, res) => {
  const v = serviceInput(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const r = db.prepare(`UPDATE services SET label = ?, lnms_port_id = ?, ${SVC_KEYS.map((k) => k + " = ?").join(", ")} WHERE id = ?`)
                 .run(v.label, v.port, ...SVC_KEYS.map((k) => v.fields[k]), intId(req.params.id));
  if (!r.changes) return res.sendStatus(404);
  cache.clear(); trafficCache.clear();
  res.json({ ok: true });
});

app.delete("/api/admin/services/:id", requireAdmin, (req, res) => {
  const r = db.prepare("DELETE FROM services WHERE id = ?").run(intId(req.params.id));
  if (!r.changes) return res.sendStatus(404);
  res.json({ ok: true });
});

// Pencarian port di LibreNMS (membantu admin menemukan port_id)
let portIndex = { t: 0, rows: [] };
async function loadPorts() {
  if (Date.now() - portIndex.t < 60 * 1000) return portIndex.rows;
  const [p, d] = await Promise.all([
    lnmsGet("/ports", "columns=port_id,device_id,ifName,ifAlias"),
    lnmsGet("/devices", "columns=device_id,hostname,sysName"),
  ]);
  if (!p.r?.ok) throw new Error(`LibreNMS ${p.r?.status || "tidak terjangkau"}`);
  const devs = new Map();
  if (d.r?.ok) for (const x of (await d.r.json()).devices || []) devs.set(x.device_id, x.sysName || x.hostname);
  const rows = ((await p.r.json()).ports || []).map((x) => ({
    port_id: x.port_id,
    device: devs.get(x.device_id) || `device ${x.device_id}`,
    ifName: x.ifName || "",
    ifAlias: x.ifAlias || "",
  }));
  portIndex = { t: Date.now(), rows };
  return rows;
}

app.get("/api/admin/ports", requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().toLowerCase();
    const rows = await loadPorts();
    const hits = q
      ? rows.filter((r) => `${r.device} ${r.ifName} ${r.ifAlias} ${r.port_id}`.toLowerCase().includes(q))
      : rows;
    res.json(hits.slice(0, 30));
  } catch (e) {
    console.error("[LNMS] cari port gagal:", e.message);
    res.status(502).json({ error: "Could not fetch the port list from LibreNMS. Enter the Port ID manually." });
  }
});

// Satu halaman (public/index.html) untuk login, dashboard, dan admin.
// Alamat lama diarahkan ke "/" supaya bookmark lama tetap jalan.
app.get(["/login.html", "/dashboard.html", "/admin.html"], (req, res) => res.redirect("/"));
app.use(express.static("public"));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Portal jalan di http://localhost:${port}`));