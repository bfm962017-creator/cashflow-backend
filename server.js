'use strict';
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL;
const SECRET = process.env.JWT_SECRET;
if (!DB_URL) { console.error('DATABASE_URL is required'); process.exit(1); }
if (!SECRET) { console.error('JWT_SECRET is required'); process.exit(1); }

const pool = new Pool({
  connectionString: DB_URL,
  ssl: /\.render\.com/.test(DB_URL) ? { rejectUnauthorized: false } : undefined,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  pass_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tx (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('in','out')),
  amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  tx_date TEXT NOT NULL,
  tx_time TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  descr TEXT NOT NULL DEFAULT '',
  ts BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS tx_user_idx ON tx (username);
CREATE INDEX IF NOT EXISTS tx_date_idx ON tx (tx_date);
ALTER TABLE users ADD COLUMN IF NOT EXISTS seen_at BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS activity (
  id BIGSERIAL PRIMARY KEY,
  ts BIGINT NOT NULL,
  actor TEXT NOT NULL,
  owner TEXT NOT NULL,
  action TEXT NOT NULL,
  kind TEXT,
  amount NUMERIC(14,2),
  prev_amount NUMERIC(14,2),
  notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS activity_ts_idx ON activity (ts DESC);
CREATE INDEX IF NOT EXISTS activity_owner_idx ON activity (owner, ts DESC);
CREATE TABLE IF NOT EXISTS settings (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  name TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  logo TEXT,
  updated BIGINT NOT NULL DEFAULT 0
);
INSERT INTO settings (id) VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS parties (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'customer' CHECK (kind IN ('customer','supplier','staff','other')),
  ts BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS parties_owner_idx ON parties (owner);
ALTER TABLE parties ADD COLUMN IF NOT EXISTS due TEXT NOT NULL DEFAULT '';
ALTER TABLE tx ADD COLUMN IF NOT EXISTS party_id TEXT;
CREATE INDEX IF NOT EXISTS tx_party_idx ON tx (party_id);
CREATE TABLE IF NOT EXISTS tx_history (
  id BIGSERIAL PRIMARY KEY,
  tx_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  ts BIGINT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('add','edit','delete','restore')),
  changes JSONB,
  snapshot JSONB
);
CREATE INDEX IF NOT EXISTS tx_history_tx_idx ON tx_history (tx_id, ts);
CREATE INDEX IF NOT EXISTS tx_history_del_idx ON tx_history (action, ts DESC);
CREATE TABLE IF NOT EXISTS tx_photos (
  tx_id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  bytes INT NOT NULL,
  ts BIGINT NOT NULL
);
`;

const ORIGINS = (process.env.FRONTEND_URL || '').split(',').map((x) => x.trim().replace(/\/$/, '')).filter(Boolean);
if (!ORIGINS.length) console.warn('FRONTEND_URL is not set: browsers from other origins will be blocked by CORS');

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ORIGINS.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
// The business logo is sent as a data URL, so the settings route gets a bigger body limit.
const jsonSmall = express.json({ limit: '50kb' }), jsonBig = express.json({ limit: '400kb' });
app.use((req, res, next) => (req.path === '/api/settings' || /^\/api\/tx\/[^/]+\/photo$/.test(req.path) ? jsonBig : jsonSmall)(req, res, next));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (req.path.startsWith('/api')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const uname = (s) => String(s || '').trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '');
const sign = (u) => jwt.sign({ sub: u }, SECRET, { expiresIn: '7d', algorithm: 'HS256' });
const rowTx = (r) => ({
  id: r.id, user: r.username, type: r.kind, amount: Number(r.amount),
  date: r.tx_date, time: r.tx_time, notes: r.notes, desc: r.descr, ts: Number(r.ts),
  party: r.party_id || null, edited: !!r.edited, photo: !!r.has_photo,
});
const rowParty = (r) => ({ id: r.id, owner: r.owner, name: r.name, phone: r.phone, kind: r.kind, due: r.due || '', ts: Number(r.ts) });
const rowAct = (r) => ({
  id: Number(r.id), ts: Number(r.ts), actor: r.actor, owner: r.owner, action: r.action, type: r.kind,
  amount: r.amount == null ? null : Number(r.amount), prev: r.prev_amount == null ? null : Number(r.prev_amount), notes: r.notes,
});
// Records who did what for the notification feed. A failed write never fails the request itself.
// action: tx_add | tx_edit | tx_delete | tx_restore | user_add | user_delete | user_password | settings
// Entry history: every add / edit / delete / restore is stored with who, when and what changed.
// Edits keep only the fields that changed ({field: [old, new]}); add/delete keep the whole row.
const HIST_FIELDS = ['kind', 'amount', 'tx_date', 'tx_time', 'notes', 'descr', 'party_id'];
const snap = (r) => ({ id: r.id, username: r.username, kind: r.kind, amount: Number(r.amount), tx_date: r.tx_date, tx_time: r.tx_time,
  notes: r.notes, descr: r.descr, ts: Number(r.ts), party_id: r.party_id || null });
async function logHist(txRow, actor, action, before) {
  try {
    let changes = null;
    if (action === 'edit') {
      const a = snap(before), b = snap(txRow);
      changes = {};
      HIST_FIELDS.forEach((f) => { if (String(a[f] ?? '') !== String(b[f] ?? '')) changes[f] = [a[f], b[f]]; });
      if (!Object.keys(changes).length) return;
    }
    await pool.query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes, snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [txRow.id, txRow.username, Date.now(), actor, action, changes, action === 'edit' ? null : snap(txRow)]);
  } catch (e) { console.error('history log failed:', e.message); }
}
async function logAct(actor, owner, action, tx, prev) {
  try {
    await pool.query(
      'INSERT INTO activity (ts, actor, owner, action, kind, amount, prev_amount, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [Date.now(), actor, owner, action, tx ? tx.kind : null, tx ? tx.amount : null, prev == null ? null : prev, tx ? (tx.notes || tx.descr || '') : '']);
  } catch (e) { console.error('activity log failed:', e.message); }
}
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

// simple login throttle: 8 failures / 15 min per ip+username
const fails = new Map();
const WINDOW = 15 * 60 * 1000;
const limited = (k) => { const e = fails.get(k); return !!e && e.n >= 8 && Date.now() - e.t < WINDOW; };
const addFail = (k) => {
  const e = fails.get(k) || { n: 0, t: 0 };
  if (Date.now() - e.t > WINDOW) e.n = 0;
  e.n++; e.t = Date.now(); fails.set(k, e);
};
setInterval(() => { const n = Date.now(); for (const [k, v] of fails) if (n - v.t > WINDOW) fails.delete(k); }, 10 * 60 * 1000).unref();

const auth = wrap(async (req, res, next) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return res.status(401).json({ error: 'Not signed in' });
  let p;
  try { p = jwt.verify(m[1], SECRET, { algorithms: ['HS256'] }); }
  catch { return res.status(401).json({ error: 'Session expired' }); }
  const { rows } = await pool.query('SELECT username, role, seen_at FROM users WHERE username = $1', [p.sub]);
  if (!rows.length) return res.status(401).json({ error: 'Account no longer exists' });
  req.user = rows[0];
  next();
});
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

app.get('/health', (req, res) => res.type('text').send('ok'));

app.get('/api/bootstrap', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT count(*)::int AS c FROM users');
  res.json({ needsSetup: rows[0].c === 0 });
}));

app.post('/api/setup', wrap(async (req, res) => {
  const u = uname(req.body.username), p = String(req.body.password || '');
  if (!u) return res.status(400).json({ error: 'Enter a username' });
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(p, 10);
  const r = await pool.query(
    "INSERT INTO users (username, role, pass_hash) SELECT $1::text, 'admin', $2::text WHERE NOT EXISTS (SELECT 1 FROM users) RETURNING username",
    [u, hash]);
  if (!r.rowCount) return res.status(409).json({ error: 'Setup already completed' });
  res.json({ token: sign(u) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const u = uname(req.body.username), p = String(req.body.password || ''), key = req.ip + '|' + u;
  if (limited(key)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { rows } = await pool.query('SELECT username, pass_hash FROM users WHERE username = $1', [u]);
  const ok = await bcrypt.compare(p, rows.length ? rows[0].pass_hash : DUMMY_HASH);
  if (!rows.length || !ok) { addFail(key); return res.status(401).json({ error: 'Wrong username or password' }); }
  fails.delete(key);
  res.json({ token: sign(u) });
}));

const TX_SELECT = "SELECT tx.*, EXISTS (SELECT 1 FROM tx_history h WHERE h.tx_id = tx.id AND h.action = 'edit') AS edited, " +
  "EXISTS (SELECT 1 FROM tx_photos ph WHERE ph.tx_id = tx.id) AS has_photo FROM tx";
app.get('/api/data', auth, wrap(async (req, res) => {
  const admin = req.user.role === 'admin';
  const t = admin
    ? await pool.query(TX_SELECT + ' ORDER BY tx_date, tx_time, ts')
    : await pool.query(TX_SELECT + ' WHERE username = $1 ORDER BY tx_date, tx_time, ts', [req.user.username]);
  const users = {};
  if (admin) {
    (await pool.query('SELECT username, role FROM users ORDER BY username')).rows
      .forEach((r) => { users[r.username] = { name: r.username, role: r.role }; });
  } else {
    users[req.user.username] = { name: req.user.username, role: req.user.role };
  }
  const a = admin
    ? await pool.query('SELECT * FROM activity ORDER BY ts DESC LIMIT 50')
    : await pool.query('SELECT * FROM activity WHERE owner = $1 ORDER BY ts DESC LIMIT 50', [req.user.username]);
  res.json({
    me: { name: req.user.username, role: req.user.role }, users, txs: t.rows.map(rowTx),
    activity: a.rows.map(rowAct), seenAt: Number(req.user.seen_at),
    biz: await bizInfo(false),
    // Users get only their own parties; the admin also gets everyone's, read-only (edits stay owner-only).
    photoBytes: admin ? Number((await pool.query('SELECT COALESCE(SUM(bytes),0) AS b FROM tx_photos')).rows[0].b) : undefined,
    parties: (admin
      ? await pool.query('SELECT * FROM parties ORDER BY owner, lower(name)')
      : await pool.query('SELECT * FROM parties WHERE owner = $1 ORDER BY lower(name)', [req.user.username])).rows.map(rowParty),
  });
}));

// Business settings (name, address, logo) are shared by everyone; only the admin can change them.
// /api/data carries name/address and a version number; the logo is fetched here only when that changes.
async function bizInfo(withLogo) {
  const { rows } = await pool.query('SELECT name, address, logo, updated FROM settings WHERE id = 1');
  const r = rows[0] || { name: '', address: '', logo: null, updated: 0 };
  const out = { name: r.name, address: r.address, hasLogo: !!r.logo, v: Number(r.updated) };
  if (withLogo) out.logo = r.logo || null;
  return out;
}

app.get('/api/settings', auth, wrap(async (req, res) => res.json(await bizInfo(true))));

app.put('/api/settings', auth, adminOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const address = String(req.body.address || '').trim().slice(0, 300);
  const logo = req.body.logo;
  if (logo != null && logo !== '' && !(typeof logo === 'string' && logo.length <= 400000 &&
      /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(logo)))
    return res.status(400).json({ error: 'Logo must be a PNG or JPEG image under 300 KB' });
  if (logo === undefined)
    await pool.query('UPDATE settings SET name = $1, address = $2, updated = $3 WHERE id = 1', [name, address, Date.now()]);
  else
    await pool.query('UPDATE settings SET name = $1, address = $2, logo = $3, updated = $4 WHERE id = 1', [name, address, logo || null, Date.now()]);
  await logAct(req.user.username, req.user.username, 'settings');
  res.json(await bizInfo(true));
}));

app.post('/api/activity/seen', auth, wrap(async (req, res) => {
  const now = Date.now();
  await pool.query('UPDATE users SET seen_at = $2 WHERE username = $1', [req.user.username, now]);
  res.json({ seenAt: now });
}));

function parseTx(b) {
  const type = b.type, amount = Math.round(Number(b.amount) * 100) / 100;
  const date = String(b.date || ''), time = String(b.time || '');
  const notes = String(b.notes || '').trim().slice(0, 500), desc = String(b.desc || '').trim().slice(0, 500);
  if (type !== 'in' && type !== 'out') return { error: 'Invalid type' };
  if (!(amount > 0 && amount < 1e11)) return { error: 'Enter a valid amount' };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(Date.parse(date))) return { error: 'Invalid date' };
  if (time && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return { error: 'Invalid time' };
  const party = b.party ? String(b.party) : null;
  return { v: { type, amount, date, time, notes, desc, party } };
}
// A party can only be attached to entries in the cashbook of the user who added that party.
async function partyOk(party, owner) {
  if (!party) return true;
  const r = await pool.query('SELECT 1 FROM parties WHERE id = $1 AND owner = $2', [party, owner]);
  return r.rowCount > 0;
}

app.post('/api/tx', auth, wrap(async (req, res) => {
  const p = parseTx(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  let owner = req.user.username;
  if (req.user.role === 'admin' && req.body.user) {
    owner = uname(req.body.user);
    const e = await pool.query('SELECT 1 FROM users WHERE username = $1', [owner]);
    if (!e.rowCount) return res.status(400).json({ error: 'Unknown user' });
  }
  const v = p.v, id = crypto.randomUUID();
  if (!(await partyOk(v.party, owner))) return res.status(400).json({ error: 'Unknown party' });
  const { rows } = await pool.query(
    'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts, party_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
    [id, owner, v.type, v.amount, v.date, v.time, v.notes, v.desc, Date.now(), v.party]);
  await logAct(req.user.username, owner, 'tx_add', rows[0]);
  await logHist(rows[0], req.user.username, 'add');
  res.json(rowTx(rows[0]));
}));

app.put('/api/tx/:id', auth, wrap(async (req, res) => {
  const p = parseTx(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const cur = await pool.query('SELECT * FROM tx WHERE id = $1', [req.params.id]);
  if (!cur.rowCount || (req.user.role !== 'admin' && cur.rows[0].username !== req.user.username))
    return res.status(404).json({ error: 'Entry not found' });
  const v = p.v;
  if (!(await partyOk(v.party, cur.rows[0].username))) return res.status(400).json({ error: 'Unknown party' });
  const { rows } = await pool.query(
    'UPDATE tx SET kind=$2, amount=$3, tx_date=$4, tx_time=$5, notes=$6, descr=$7, party_id=$8 WHERE id=$1 RETURNING *',
    [req.params.id, v.type, v.amount, v.date, v.time, v.notes, v.desc, v.party]);
  await logAct(req.user.username, rows[0].username, 'tx_edit', rows[0], cur.rows[0].amount);
  await logHist(rows[0], req.user.username, 'edit', cur.rows[0]);
  res.json(rowTx({ ...rows[0], edited: true }));
}));

app.delete('/api/tx/:id', auth, wrap(async (req, res) => {
  const r = req.user.role === 'admin'
    ? await pool.query('DELETE FROM tx WHERE id = $1 RETURNING *', [req.params.id])
    : await pool.query('DELETE FROM tx WHERE id = $1 AND username = $2 RETURNING *', [req.params.id, req.user.username]);
  if (!r.rowCount) return res.status(404).json({ error: 'Entry not found' });
  await logAct(req.user.username, r.rows[0].username, 'tx_delete', r.rows[0]);
  await logHist(r.rows[0], req.user.username, 'delete');
  res.json({ ok: true });
}));

// History of one entry: its owner and the admin can read it. Works for deleted entries too.
app.get('/api/tx/:id/history', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tx_history WHERE tx_id = $1 ORDER BY ts DESC, id DESC', [req.params.id]);
  const cur = await pool.query('SELECT username FROM tx WHERE id = $1', [req.params.id]);
  const owner = cur.rows.length ? cur.rows[0].username : rows.length ? rows[0].owner : null;
  if (!owner || (req.user.role !== 'admin' && owner !== req.user.username)) return res.status(404).json({ error: 'Entry not found' });
  res.json(rows.map((h) => ({ id: Number(h.id), ts: Number(h.ts), actor: h.actor, action: h.action, changes: h.changes, snapshot: h.snapshot })));
}));

// Bill photos: one compressed JPEG per entry, stored apart from the entry so lists stay light.
// Only the entry's owner and the admin can read or change it. Photos of deleted entries are kept
// while the entry can still be restored (30 days) and cleaned up on startup after that.
async function txOwnerOk(req, id) {
  const r = await pool.query('SELECT username, ts FROM tx WHERE id = $1', [id]);
  return r.rows.length && (req.user.role === 'admin' || r.rows[0].username === req.user.username) ? r.rows[0] : null;
}
app.get('/api/tx/:id/photo', auth, wrap(async (req, res) => {
  if (!(await txOwnerOk(req, req.params.id))) return res.status(404).json({ error: 'Entry not found' });
  const { rows } = await pool.query('SELECT data FROM tx_photos WHERE tx_id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'No photo' });
  res.set('Cache-Control', 'private, max-age=86400').json({ photo: rows[0].data });
}));
app.put('/api/tx/:id/photo', auth, wrap(async (req, res) => {
  const tx = await txOwnerOk(req, req.params.id);
  if (!tx) return res.status(404).json({ error: 'Entry not found' });
  const photo = req.body.photo;
  if (!(typeof photo === 'string' && photo.length <= 400000 && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(photo)))
    return res.status(400).json({ error: 'Photo must be a JPEG under 300 KB' });
  const had = (await pool.query('SELECT 1 FROM tx_photos WHERE tx_id = $1', [req.params.id])).rowCount > 0;
  const bytes = Math.round((photo.length - 23) * 3 / 4);
  await pool.query('INSERT INTO tx_photos (tx_id, data, bytes, ts) VALUES ($1,$2,$3,$4) ON CONFLICT (tx_id) DO UPDATE SET data = $2, bytes = $3, ts = $4',
    [req.params.id, photo, bytes, Date.now()]);
  // A photo attached while the entry is being created is part of adding it, not an edit.
  if (had || Date.now() - Number(tx.ts) > 120000)
    await pool.query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.params.id, tx.username, Date.now(), req.user.username, 'edit', { photo: [had ? 'yes' : null, had ? 'replaced' : 'added'] }]);
  res.json({ ok: true, bytes });
}));
app.delete('/api/tx/:id/photo', auth, wrap(async (req, res) => {
  const tx = await txOwnerOk(req, req.params.id);
  if (!tx) return res.status(404).json({ error: 'Entry not found' });
  const r = await pool.query('DELETE FROM tx_photos WHERE tx_id = $1', [req.params.id]);
  if (r.rowCount) await pool.query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes) VALUES ($1,$2,$3,$4,$5,$6)',
    [req.params.id, tx.username, Date.now(), req.user.username, 'edit', { photo: ['yes', null] }]);
  res.json({ ok: true });
}));

// Deleted entries (admin): deletions from the last 30 days that have not been restored.
app.get('/api/deleted', auth, adminOnly, wrap(async (req, res) => {
  const since = Date.now() - 30 * 86400000;
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (h.tx_id) h.* FROM tx_history h
     WHERE h.action = 'delete' AND h.ts > $1 AND NOT EXISTS (SELECT 1 FROM tx WHERE tx.id = h.tx_id)
     ORDER BY h.tx_id, h.ts DESC`, [since]);
  rows.sort((a, b) => Number(b.ts) - Number(a.ts));
  res.json(rows.map((h) => ({ id: Number(h.id), ts: Number(h.ts), actor: h.actor, snapshot: h.snapshot })));
}));

app.post('/api/deleted/:id/restore', auth, adminOnly, wrap(async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM tx_history WHERE id = $1 AND action = 'delete'", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  const s = rows[0].snapshot;
  const exists = await pool.query('SELECT 1 FROM tx WHERE id = $1', [s.id]);
  if (exists.rowCount) return res.status(409).json({ error: 'This entry is already back' });
  const pty = s.party_id ? (await pool.query('SELECT 1 FROM parties WHERE id = $1 AND owner = $2', [s.party_id, s.username])).rowCount ? s.party_id : null : null;
  const r = await pool.query(
    'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts, party_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
    [s.id, s.username, s.kind, s.amount, s.tx_date, s.tx_time, s.notes, s.descr, s.ts, pty]);
  await logHist(r.rows[0], req.user.username, 'restore');
  await logAct(req.user.username, s.username, 'tx_restore', r.rows[0]);
  res.json(rowTx(r.rows[0]));
}));

// Parties (customers, suppliers, staff): only the user who added a party can change it; the admin can view all.
function parseParty(b) {
  const name = String(b.name || '').trim().slice(0, 80), phone = String(b.phone || '').replace(/[^\d+ ]/g, '').trim().slice(0, 20);
  const kind = ['customer', 'supplier', 'staff', 'other'].includes(b.kind) ? b.kind : 'customer';
  // Optional payment due date (YYYY-MM-DD); empty clears it.
  const due = /^\d{4}-\d{2}-\d{2}$/.test(b.due || '') && !isNaN(Date.parse(b.due)) ? b.due : '';
  if (!name) return { error: 'Enter a name' };
  return { v: { name, phone, kind, due } };
}
app.post('/api/parties', auth, wrap(async (req, res) => {
  const p = parseParty(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const dup = await pool.query('SELECT 1 FROM parties WHERE owner = $1 AND lower(name) = lower($2)', [req.user.username, p.v.name]);
  if (dup.rowCount) return res.status(409).json({ error: 'You already have a party with that name' });
  const { rows } = await pool.query('INSERT INTO parties (id, owner, name, phone, kind, due, ts) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [crypto.randomUUID(), req.user.username, p.v.name, p.v.phone, p.v.kind, p.v.due, Date.now()]);
  res.json(rowParty(rows[0]));
}));
app.put('/api/parties/:id', auth, wrap(async (req, res) => {
  const p = parseParty(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const dup = await pool.query('SELECT 1 FROM parties WHERE owner = $1 AND lower(name) = lower($2) AND id <> $3', [req.user.username, p.v.name, req.params.id]);
  if (dup.rowCount) return res.status(409).json({ error: 'You already have a party with that name' });
  const { rows } = await pool.query('UPDATE parties SET name = $3, phone = $4, kind = $5, due = $6 WHERE id = $1 AND owner = $2 RETURNING *',
    [req.params.id, req.user.username, p.v.name, p.v.phone, p.v.kind, p.v.due]);
  if (!rows.length) return res.status(404).json({ error: 'Party not found' });
  res.json(rowParty(rows[0]));
}));
app.delete('/api/parties/:id', auth, wrap(async (req, res) => {
  const mine = await pool.query('SELECT 1 FROM parties WHERE id = $1 AND owner = $2', [req.params.id, req.user.username]);
  if (!mine.rowCount) return res.status(404).json({ error: 'Party not found' });
  const used = await pool.query('SELECT 1 FROM tx WHERE party_id = $1 LIMIT 1', [req.params.id]);
  if (used.rowCount) return res.status(409).json({ error: 'This party has entries. Delete those entries first.' });
  await pool.query('DELETE FROM parties WHERE id = $1 AND owner = $2', [req.params.id, req.user.username]);
  res.json({ ok: true });
}));

app.post('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const u = uname(req.body.username), p = String(req.body.password || '');
  if (!u) return res.status(400).json({ error: 'Enter a username' });
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(p, 10);
  const r = await pool.query(
    "INSERT INTO users (username, role, pass_hash) VALUES ($1,'user',$2) ON CONFLICT DO NOTHING RETURNING username", [u, hash]);
  if (!r.rowCount) return res.status(409).json({ error: 'Username already exists' });
  await logAct(req.user.username, u, 'user_add');
  res.json({ ok: true });
}));

app.put('/api/users/:name/password', auth, adminOnly, wrap(async (req, res) => {
  const p = String(req.body.password || '');
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const r = await pool.query('UPDATE users SET pass_hash = $2 WHERE username = $1',
    [uname(req.params.name), await bcrypt.hash(p, 10)]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  await logAct(req.user.username, uname(req.params.name), 'user_password');
  res.json({ ok: true });
}));

app.delete('/api/users/:name', auth, adminOnly, wrap(async (req, res) => {
  const r = await pool.query("DELETE FROM users WHERE username = $1 AND role <> 'admin'", [uname(req.params.name)]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found (admin cannot be deleted)' });
  await logAct(req.user.username, uname(req.params.name), 'user_delete');
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.get('/', (req, res) => res.json({ name: 'cashflow-api', ok: true }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'That is too large to upload' });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

(async () => {
  for (let i = 1; ; i++) {
    try { await pool.query(SCHEMA); break; }
    catch (e) {
      console.error('DB init failed (attempt ' + i + '):', e.message);
      if (i >= 10) process.exit(1);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  // Drop photos of entries deleted more than 30 days ago (they can no longer be restored).
  pool.query(`DELETE FROM tx_photos p WHERE NOT EXISTS (SELECT 1 FROM tx WHERE tx.id = p.tx_id)
    AND NOT EXISTS (SELECT 1 FROM tx_history h WHERE h.tx_id = p.tx_id AND h.action = 'delete' AND h.ts > $1)`, [Date.now() - 30 * 86400000])
    .catch((e) => console.error('photo cleanup failed:', e.message));
  app.listen(PORT, '0.0.0.0', () => console.log('Cashflow listening on ' + PORT));
})();
