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
ALTER TABLE settings ADD COLUMN IF NOT EXISTS lock_days INT NOT NULL DEFAULT -1;
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
ALTER TABLE parties ADD COLUMN IF NOT EXISTS common BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tx ADD COLUMN IF NOT EXISTS party_id TEXT;
ALTER TABLE tx ADD COLUMN IF NOT EXISTS transfer_id TEXT;
CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY,
  from_user TEXT NOT NULL,
  to_user TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  tx_date TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected','cancelled','deleted')),
  ts BIGINT NOT NULL,
  done_ts BIGINT
);
CREATE INDEX IF NOT EXISTS transfers_from_idx ON transfers (from_user);
CREATE INDEX IF NOT EXISTS transfers_to_idx ON transfers (to_user);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS req_kind TEXT;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS req_by TEXT;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS req_amount NUMERIC(14,2);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS req_notes TEXT;
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS req_ts BIGINT;
CREATE TABLE IF NOT EXISTS meta (id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), rev BIGINT NOT NULL DEFAULT 0);
INSERT INTO meta (id) VALUES (1) ON CONFLICT DO NOTHING;
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
// Every successful change bumps one revision number. Phones poll /api/rev (a few bytes) and only
// download everything again when it moved, instead of pulling all entries every 20 seconds.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'OPTIONS' && !/^\/(login|activity\/seen)$/.test(req.path))
    res.on('finish', () => { if (res.statusCode < 400) pool.query('UPDATE meta SET rev = rev + 1 WHERE id = 1').catch(() => {}); });
  next();
});
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
  party: r.party_id || null, edited: !!r.edited, photo: !!r.has_photo, transfer: r.transfer_id || null,
});
const rowTr = (r) => ({ id: r.id, from: r.from_user, to: r.to_user, amount: Number(r.amount), date: r.tx_date, notes: r.notes,
  status: r.status, ts: Number(r.ts), doneTs: r.done_ts == null ? null : Number(r.done_ts),
  req: r.req_kind ? { kind: r.req_kind, by: r.req_by, amount: r.req_amount == null ? null : Number(r.req_amount), notes: r.req_notes || '', ts: Number(r.req_ts) } : null });
const rowParty = (r) => ({ id: r.id, owner: r.owner, name: r.name, phone: r.phone, kind: r.kind, due: r.due || '', common: !!r.common, ts: Number(r.ts) });
const rowAct = (r) => ({
  id: Number(r.id), ts: Number(r.ts), actor: r.actor, owner: r.owner, action: r.action, type: r.kind,
  amount: r.amount == null ? null : Number(r.amount), prev: r.prev_amount == null ? null : Number(r.prev_amount), notes: r.notes,
});
// Records who did what for the notification feed. A failed write never fails the request itself.
// action: lock | tr_req | tr_req_agree | tr_req_refuse | tr_req_withdraw | tx_add | tx_edit | tx_delete | tx_restore | user_add | user_delete | user_password | settings | tr_send | tr_accept | tr_reject | tr_cancel
// Entry history: every add / edit / delete / restore is stored with who, when and what changed.
// Edits keep only the fields that changed ({field: [old, new]}); add/delete keep the whole row.
const HIST_FIELDS = ['kind', 'amount', 'tx_date', 'tx_time', 'notes', 'descr', 'party_id'];
const snap = (r) => ({ id: r.id, username: r.username, kind: r.kind, amount: Number(r.amount), tx_date: r.tx_date, tx_time: r.tx_time,
  notes: r.notes, descr: r.descr, ts: Number(r.ts), party_id: r.party_id || null, transfer_id: r.transfer_id || null });
// With db (a transaction client) a failure undoes the whole change, so an entry never changes
// without its history record; without it, a failed history write is only logged.
async function logHist(txRow, actor, action, before, db) {
  let changes = null;
  if (action === 'edit') {
    const a = snap(before), b = snap(txRow);
    changes = {};
    HIST_FIELDS.forEach((f) => { if (String(a[f] ?? '') !== String(b[f] ?? '')) changes[f] = [a[f], b[f]]; });
    if (!Object.keys(changes).length) return;
  }
  const run = () => (db || pool).query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes, snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [txRow.id, txRow.username, Date.now(), actor, action, changes, action === 'edit' ? null : snap(txRow)]);
  if (db) return run();
  try { await run(); } catch (e) { console.error('history log failed:', e.message); }
}
// Runs fn(client) as one database transaction: either every step is saved or none is.
async function atomic(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); const out = await fn(c); await c.query('COMMIT'); return out; }
  catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}
// A real calendar date as YYYY-MM-DD (rejects impossible ones like 2026-02-31).
const validDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s)) &&
  new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) === s;
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
const noAdmin = (msg) => (req, res, next) =>
  req.user.role === 'user' ? next() : res.status(403).json({ error: msg });
const TRANSFER_USERS = 'Transfers are only between users';

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
    ? await pool.query('SELECT * FROM activity ORDER BY ts DESC LIMIT 100')
    : await pool.query('SELECT * FROM activity WHERE owner = $1 ORDER BY ts DESC LIMIT 100', [req.user.username]);
  res.json({
    rev: Number((await pool.query('SELECT rev FROM meta WHERE id = 1')).rows[0].rev),
    me: { name: req.user.username, role: req.user.role }, users, txs: t.rows.map(rowTx),
    activity: a.rows.map(rowAct), seenAt: Number(req.user.seen_at),
    biz: await bizInfo(false),
    // Users get their own parties plus the common ones; the admin gets everything.
    photoBytes: admin ? Number((await pool.query('SELECT COALESCE(SUM(bytes),0) AS b FROM tx_photos')).rows[0].b) : undefined,
    parties: (admin
      ? await pool.query('SELECT * FROM parties ORDER BY owner, lower(name)')
      : await pool.query('SELECT * FROM parties WHERE owner = $1 OR common ORDER BY lower(name)', [req.user.username])).rows.map(rowParty),
    // Common parties keep one combined ledger: users also get other users' entries with them (read-only).
    ctxs: admin ? [] : (await pool.query(TX_SELECT + ' WHERE username <> $1 AND party_id IN (SELECT id FROM parties WHERE common) ORDER BY tx_date, tx_time, ts',
      [req.user.username])).rows.map(rowTx),
    // Transfers: users see the ones they sent or received; the admin sees all (read-only).
    // Anything still waiting on someone is always included; finished ones only the latest 100 / 200.
    transfers: (admin
      ? await pool.query(`SELECT * FROM transfers WHERE status = 'pending' OR req_kind IS NOT NULL
          UNION SELECT * FROM (SELECT * FROM transfers ORDER BY ts DESC LIMIT 200) x ORDER BY ts DESC`)
      : await pool.query(`SELECT * FROM transfers WHERE (from_user = $1 OR to_user = $1) AND (status = 'pending' OR req_kind IS NOT NULL)
          UNION SELECT * FROM (SELECT * FROM transfers WHERE from_user = $1 OR to_user = $1 ORDER BY ts DESC LIMIT 100) x ORDER BY ts DESC`, [req.user.username])).rows.map(rowTr),
    // Other (non-admin) users a user can send a transfer to.
    peers: admin ? [] : (await pool.query("SELECT username FROM users WHERE role = 'user' AND username <> $1 ORDER BY username", [req.user.username])).rows.map((x) => x.username),
  });
}));

// Business settings (name, address, logo) are shared by everyone; only the admin can change them.
// /api/data carries name/address and a version number; the logo is fetched here only when that changes.
async function bizInfo(withLogo) {
  const { rows } = await pool.query('SELECT name, address, logo, updated, lock_days FROM settings WHERE id = 1');
  const r = rows[0] || { name: '', address: '', logo: null, updated: 0, lock_days: -1 };
  const out = { name: r.name, address: r.address, hasLogo: !!r.logo, v: Number(r.updated), lock: Number(r.lock_days) };
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

app.get('/api/rev', auth, wrap(async (req, res) => {
  res.json({ rev: Number((await pool.query('SELECT rev FROM meta WHERE id = 1')).rows[0].rev) });
}));

app.post('/api/activity/seen', auth, wrap(async (req, res) => {
  const now = Date.now();
  await pool.query('UPDATE users SET seen_at = $2 WHERE username = $1', [req.user.username, now]);
  res.json({ seenAt: now });
}));

// Lock old entries: when on, users (never the admin) cannot add, change or delete entries dated
// before the cut-off. lock_days: -1 = off, 0 = only today's entries, N = today and the N days before.
// Dates are counted in India time, which is what the app's users see.
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const istToday = () => new Date(Date.now() + 330 * 60000).toISOString().slice(0, 10);
function cutoffFor(days) { const t = new Date(istToday() + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() - days); return t.toISOString().slice(0, 10); }
async function lockCutoff(req) {
  if (req.user.role === 'admin') return null;
  const d = Number((await pool.query('SELECT lock_days FROM settings WHERE id = 1')).rows[0]?.lock_days ?? -1);
  return d < 0 ? null : cutoffFor(d);
}
const locked = (res, c) => res.status(403).json({ error: 'Locked: entries before ' + +c.slice(8) + ' ' + MON[+c.slice(5, 7) - 1] + ' ' + c.slice(0, 4) + ' can only be changed by the admin' });

app.put('/api/lock', auth, adminOnly, wrap(async (req, res) => {
  const d = Math.round(Number(req.body.days));
  if (!(d >= -1 && d <= 365)) return res.status(400).json({ error: 'Invalid number of days' });
  await pool.query('UPDATE settings SET lock_days = $1 WHERE id = 1', [d]);
  await logAct(req.user.username, req.user.username, 'lock', { kind: null, amount: d, notes: '' });
  res.json({ lock: d });
}));

function parseTx(b) {
  const type = b.type, amount = Math.round(Number(b.amount) * 100) / 100;
  const date = String(b.date || ''), time = String(b.time || '');
  const notes = String(b.notes || '').trim().slice(0, 500), desc = String(b.desc || '').trim().slice(0, 500);
  if (type !== 'in' && type !== 'out') return { error: 'Invalid type' };
  if (!(amount > 0 && amount < 1e11)) return { error: 'Enter a valid amount' };
  if (!validDate(date)) return { error: 'Invalid date' };
  if (time && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return { error: 'Invalid time' };
  const party = b.party ? String(b.party) : null;
  return { v: { type, amount, date, time, notes, desc, party } };
}
// An entry can use a party its cashbook's user added, or any common party.
async function partyOk(party, owner) {
  if (!party) return true;
  const r = await pool.query('SELECT 1 FROM parties WHERE id = $1 AND (owner = $2 OR common)', [party, owner]);
  return r.rowCount > 0;
}

// Only users add entries, always into their own cashbook. The admin supervises: it can read,
// correct and delete everyone's entries, but does not add any.
app.post('/api/tx', auth, noAdmin('The admin does not add entries'), wrap(async (req, res) => {
  const p = parseTx(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const owner = req.user.username;
  const v = p.v, id = crypto.randomUUID(), c = await lockCutoff(req);
  if (c && v.date < c) return locked(res, c);
  if (!(await partyOk(v.party, owner))) return res.status(400).json({ error: 'Unknown party' });
  const row = await atomic(async (c) => {
    const { rows } = await c.query(
      'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts, party_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [id, owner, v.type, v.amount, v.date, v.time, v.notes, v.desc, Date.now(), v.party]);
    await logHist(rows[0], req.user.username, 'add', null, c);
    return rows[0];
  });
  await logAct(req.user.username, owner, 'tx_add', row);
  res.json(rowTx(row));
}));

app.put('/api/tx/:id', auth, wrap(async (req, res) => {
  const p = parseTx(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const cur = await pool.query('SELECT * FROM tx WHERE id = $1', [req.params.id]);
  if (!cur.rowCount || (req.user.role !== 'admin' && cur.rows[0].username !== req.user.username))
    return res.status(404).json({ error: 'Entry not found' });
  const v = p.v, c = await lockCutoff(req);
  if (c && (cur.rows[0].tx_date < c || v.date < c)) return locked(res, c);
  if (cur.rows[0].transfer_id) {
    // A user changing a transfer needs the other user's OK (POST /api/transfers/:id/request).
    if (req.user.role !== 'admin') return res.status(409).json({ error: 'Changes to a transfer need the other user\'s OK' });
    return editTransferTx(req, res, cur.rows[0], v);
  }
  if (!(await partyOk(v.party, cur.rows[0].username))) return res.status(400).json({ error: 'Unknown party' });
  const row = await atomic(async (c) => {
    const { rows } = await c.query(
      'UPDATE tx SET kind=$2, amount=$3, tx_date=$4, tx_time=$5, notes=$6, descr=$7, party_id=$8 WHERE id=$1 RETURNING *',
      [req.params.id, v.type, v.amount, v.date, v.time, v.notes, v.desc, v.party]);
    await logHist(rows[0], req.user.username, 'edit', cur.rows[0], c);
    return rows[0];
  });
  await logAct(req.user.username, row.username, 'tx_edit', row, cur.rows[0].amount);
  res.json(rowTx({ ...row, edited: true }));
}));

// A transfer's two entries (Cash Out for the sender, Cash In for the receiver) stay identical:
// only the amount and description can change, and both entries change together.
async function changeTransfer(c, transferId, actor, amount, desc) {
  const pair = (await c.query('SELECT * FROM tx WHERE transfer_id = $1 FOR UPDATE', [transferId])).rows, out = [];
  for (const b of pair) {
    const { rows } = await c.query('UPDATE tx SET amount = $2, descr = $3 WHERE id = $1 RETURNING *', [b.id, amount, desc]);
    await logHist(rows[0], actor, 'edit', b, c);
    out.push({ before: b, after: rows[0] });
  }
  await c.query('UPDATE transfers SET amount = $2, notes = $3, req_kind = NULL, req_by = NULL, req_amount = NULL, req_notes = NULL, req_ts = NULL WHERE id = $1',
    [transferId, amount, desc]);
  return out;
}
async function removeTransfer(c, transferId, actor) {
  const gone = (await c.query('DELETE FROM tx WHERE transfer_id = $1 RETURNING *', [transferId])).rows;
  for (const g of gone) await logHist(g, actor, 'delete', null, c);
  await c.query("UPDATE transfers SET status = 'deleted', req_kind = NULL, req_by = NULL, req_amount = NULL, req_notes = NULL, req_ts = NULL WHERE id = $1", [transferId]);
  return gone;
}
async function editTransferTx(req, res, cur, v) {
  const out = await atomic((c) => changeTransfer(c, cur.transfer_id, req.user.username, v.amount, v.desc));
  for (const x of out) if (Number(x.before.amount) !== v.amount) await logAct(req.user.username, x.after.username, 'tx_edit', x.after, x.before.amount);
  const mine = out.find((x) => x.after.id === cur.id);
  res.json(rowTx({ ...(mine ? mine.after : cur), edited: true }));
}

app.delete('/api/tx/:id', auth, wrap(async (req, res) => {
  const c = await lockCutoff(req);
  if (c) {
    const o = await pool.query('SELECT tx_date FROM tx WHERE id = $1 AND username = $2', [req.params.id, req.user.username]);
    if (o.rowCount && o.rows[0].tx_date < c) return locked(res, c);
  }
  const cur = req.user.role === 'admin'
    ? await pool.query('SELECT * FROM tx WHERE id = $1', [req.params.id])
    : await pool.query('SELECT * FROM tx WHERE id = $1 AND username = $2', [req.params.id, req.user.username]);
  if (!cur.rowCount) return res.status(404).json({ error: 'Entry not found' });
  const t = cur.rows[0];
  // Deleting one side of a transfer deletes the other side too; a user needs the other user's OK.
  if (t.transfer_id && req.user.role !== 'admin') return res.status(409).json({ error: 'Deleting a transfer needs the other user\'s OK' });
  const gone = await atomic(async (c) => {
    if (t.transfer_id) return removeTransfer(c, t.transfer_id, req.user.username);
    const r = await c.query('DELETE FROM tx WHERE id = $1 RETURNING *', [t.id]);
    for (const g of r.rows) await logHist(g, req.user.username, 'delete', null, c);
    return r.rows;
  });
  if (!gone.length) return res.status(404).json({ error: 'Entry not found' });
  for (const g of gone) await logAct(req.user.username, g.username, 'tx_delete', g);
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
  const r = await pool.query('SELECT username, ts, tx_date FROM tx WHERE id = $1', [id]);
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
  const c = await lockCutoff(req);
  if (c && tx.tx_date < c) return locked(res, c);
  const photo = req.body.photo;
  if (!(typeof photo === 'string' && photo.length <= 400000 && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(photo)))
    return res.status(400).json({ error: 'Photo must be a JPEG under 300 KB' });
  const bytes = Math.round((photo.length - 23) * 3 / 4);
  await atomic(async (c) => {
    const had = (await c.query('SELECT 1 FROM tx_photos WHERE tx_id = $1', [req.params.id])).rowCount > 0;
    await c.query('INSERT INTO tx_photos (tx_id, data, bytes, ts) VALUES ($1,$2,$3,$4) ON CONFLICT (tx_id) DO UPDATE SET data = $2, bytes = $3, ts = $4',
      [req.params.id, photo, bytes, Date.now()]);
    // A photo attached while the entry is being created is part of adding it, not an edit.
    if (had || Date.now() - Number(tx.ts) > 120000)
      await c.query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, tx.username, Date.now(), req.user.username, 'edit', { photo: [had ? 'yes' : null, had ? 'replaced' : 'added'] }]);
  });
  res.json({ ok: true, bytes });
}));
app.delete('/api/tx/:id/photo', auth, wrap(async (req, res) => {
  const tx = await txOwnerOk(req, req.params.id);
  if (!tx) return res.status(404).json({ error: 'Entry not found' });
  const c = await lockCutoff(req);
  if (c && tx.tx_date < c) return locked(res, c);
  await atomic(async (c) => {
    const r = await c.query('DELETE FROM tx_photos WHERE tx_id = $1', [req.params.id]);
    if (r.rowCount) await c.query('INSERT INTO tx_history (tx_id, owner, ts, actor, action, changes) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.params.id, tx.username, Date.now(), req.user.username, 'edit', { photo: ['yes', null] }]);
  });
  res.json({ ok: true });
}));

// Deleted entries (admin): deletions from the last 30 days that have not been restored.
// Deleted entries (last 30 days): the admin sees all; a user sees only their own cashbook's.
app.get('/api/deleted', auth, wrap(async (req, res) => {
  const since = Date.now() - 30 * 86400000, admin = req.user.role === 'admin';
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (h.tx_id) h.* FROM tx_history h
     WHERE h.action = 'delete' AND h.ts > $1 AND NOT EXISTS (SELECT 1 FROM tx WHERE tx.id = h.tx_id)
     ${admin ? '' : 'AND h.owner = $2'}
     ORDER BY h.tx_id, h.ts DESC`, admin ? [since] : [since, req.user.username]);
  rows.sort((a, b) => Number(b.ts) - Number(a.ts));
  res.json(rows.map((h) => ({ id: Number(h.id), ts: Number(h.ts), actor: h.actor, snapshot: h.snapshot })));
}));

app.post('/api/deleted/:id/restore', auth, wrap(async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM tx_history WHERE id = $1 AND action = 'delete'", [req.params.id]);
  if (!rows.length || (req.user.role !== 'admin' && rows[0].owner !== req.user.username)) return res.status(404).json({ error: 'Not found' });
  const s = rows[0].snapshot, c = await lockCutoff(req);
  if (c && s.tx_date < c) return locked(res, c);
  const pty = s.party_id && (await partyOk(s.party_id, s.username)) ? s.party_id : null;
  const back = await atomic(async (c) => {
    // Lock the row id so two people restoring at once cannot both succeed.
    if ((await c.query('SELECT 1 FROM tx WHERE id = $1 FOR UPDATE', [s.id])).rowCount) return null;
    const list = [{ ...s, party_id: pty }];
    // Restoring one side of a transfer brings back the other side as well.
    if (s.transfer_id) {
      const o = await c.query(
        `SELECT snapshot FROM tx_history h WHERE action = 'delete' AND snapshot->>'transfer_id' = $1 AND tx_id <> $2
         AND NOT EXISTS (SELECT 1 FROM tx WHERE tx.id = h.tx_id) ORDER BY ts DESC LIMIT 1`, [s.transfer_id, s.id]);
      if (o.rowCount) list.push({ ...o.rows[0].snapshot, party_id: null });
      await c.query("UPDATE transfers SET status = 'accepted' WHERE id = $1", [s.transfer_id]);
    }
    const out = [];
    for (const x of list) {
      const r = await c.query(
        'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts, party_id, transfer_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
        [x.id, x.username, x.kind, x.amount, x.tx_date, x.tx_time, x.notes, x.descr, x.ts, x.party_id, x.transfer_id || null]);
      await logHist(r.rows[0], req.user.username, 'restore', null, c);
      out.push(r.rows[0]);
    }
    return out;
  }).catch((e) => { if (e.code === '23505') return null; throw e; });
  if (!back) return res.status(409).json({ error: 'This entry is already back' });
  for (const x of back) await logAct(req.user.username, x.username, 'tx_restore', x);
  res.json(rowTx(back[0]));
}));

// Transfers between users (not the admin). Nothing is added to either cashbook until the receiver
// accepts; then the sender gets a Cash Out and the receiver a Cash In, linked by transfer_id.
app.post('/api/transfers', auth, noAdmin(TRANSFER_USERS), wrap(async (req, res) => {
  const to = uname(req.body.to), amount = Math.round(Number(req.body.amount) * 100) / 100, date = String(req.body.date || '');
  const notes = String(req.body.notes || '').trim().slice(0, 200);
  if (!to || to === req.user.username) return res.status(400).json({ error: 'Choose who to send to' });
  const u = await pool.query('SELECT role FROM users WHERE username = $1', [to]);
  if (!u.rowCount || u.rows[0].role !== 'user') return res.status(400).json({ error: 'Choose who to send to' });
  if (!(amount > 0 && amount < 1e11)) return res.status(400).json({ error: 'Enter a valid amount' });
  if (!validDate(date)) return res.status(400).json({ error: 'Invalid date' });
  const c = await lockCutoff(req);
  if (c && date < c) return locked(res, c);
  const { rows } = await pool.query('INSERT INTO transfers (id, from_user, to_user, amount, tx_date, notes, ts) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [crypto.randomUUID(), req.user.username, to, amount, date, notes, Date.now()]);
  await logAct(req.user.username, to, 'tr_send', { kind: 'in', amount, notes });
  res.json(rowTr(rows[0]));
}));
// Moves a pending transfer on: the receiver accepts or rejects, the sender cancels.
async function decide(req, res, who, status, fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows } = await c.query('SELECT * FROM transfers WHERE id = $1 FOR UPDATE', [req.params.id]);
    const t = rows[0];
    if (!t || t[who] !== req.user.username) { await c.query('ROLLBACK'); return res.status(404).json({ error: 'Transfer not found' }); }
    if (t.status !== 'pending') { await c.query('ROLLBACK'); return res.status(409).json({ error: 'This transfer was already ' + t.status }); }
    const made = fn ? await fn(c, t) : [];
    for (const m of made) await logHist(m, req.user.username, 'add', null, c);
    const u = await c.query('UPDATE transfers SET status = $2, done_ts = $3 WHERE id = $1 RETURNING *', [t.id, status, Date.now()]);
    await c.query('COMMIT');
    await logAct(req.user.username, who === 'to_user' ? t.from_user : t.to_user, 'tr_' + (status === 'accepted' ? 'accept' : status === 'rejected' ? 'reject' : 'cancel'),
      { kind: who === 'to_user' ? 'out' : 'in', amount: t.amount, notes: t.notes });
    res.json(rowTr(u.rows[0]));
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
}
app.post('/api/transfers/:id/accept', auth, noAdmin(TRANSFER_USERS), wrap(async (req, res) => {
  const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(req.body.time || '') ? req.body.time : '';
  await decide(req, res, 'to_user', 'accepted', async (c, t) => {
    const ins = (user, kind, notes) => c.query(
      'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts, transfer_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [crypto.randomUUID(), user, kind, t.amount, t.tx_date, time, notes, t.notes, Date.now(), t.id]);
    return [(await ins(t.from_user, 'out', '⇄ To ' + t.to_user)).rows[0], (await ins(t.to_user, 'in', '⇄ From ' + t.from_user)).rows[0]];
  });
}));
app.post('/api/transfers/:id/reject', auth, noAdmin(TRANSFER_USERS), wrap((req, res) => decide(req, res, 'to_user', 'rejected')));
app.post('/api/transfers/:id/cancel', auth, noAdmin(TRANSFER_USERS), wrap((req, res) => decide(req, res, 'from_user', 'cancelled')));

// Changing or deleting an accepted transfer: one user asks, the other agrees or refuses.
// Until then both cashbooks stay as they are. The admin can still change transfers directly.
async function onTransfer(req, res, fn) {
  const r = await atomic(async (c) => {
    const { rows } = await c.query('SELECT * FROM transfers WHERE id = $1 FOR UPDATE', [req.params.id]);
    const t = rows[0];
    if (!t || (t.from_user !== req.user.username && t.to_user !== req.user.username)) return { code: 404, error: 'Transfer not found' };
    return fn(c, t, t.from_user === req.user.username ? t.to_user : t.from_user);
  });
  if (r.code) return res.status(r.code).json({ error: r.error });
  if (r.act) await logAct(req.user.username, r.act.owner, r.act.action, r.act.row, r.act.prev);
  for (const g of r.acts || []) await logAct(req.user.username, g.owner, g.action, g.row, g.prev);
  res.json(rowTr(r.t));
}
app.post('/api/transfers/:id/request', auth, noAdmin(TRANSFER_USERS), wrap((req, res) => onTransfer(req, res, async (c, t, other) => {
  const kind = req.body.kind;
  if (t.status !== 'accepted') return { code: 409, error: 'Only an accepted transfer can be changed' };
  if (t.req_kind) return { code: 409, error: 'A request for this transfer is already waiting' };
  if (kind !== 'edit' && kind !== 'delete') return { code: 400, error: 'Bad request' };
  const cut = await lockCutoff(req);
  if (cut && t.tx_date < cut) return { code: 403, error: 'Locked: entries before ' + +cut.slice(8) + ' ' + MON[+cut.slice(5, 7) - 1] + ' ' + cut.slice(0, 4) + ' can only be changed by the admin' };
  let amount = null, notes = null;
  if (kind === 'edit') {
    amount = Math.round(Number(req.body.amount) * 100) / 100; notes = String(req.body.notes || '').trim().slice(0, 500);
    if (!(amount > 0 && amount < 1e11)) return { code: 400, error: 'Enter a valid amount' };
    if (amount === Number(t.amount) && notes === t.notes) return { code: 400, error: 'Nothing was changed' };
  }
  const u = await c.query('UPDATE transfers SET req_kind = $2, req_by = $3, req_amount = $4, req_notes = $5, req_ts = $6 WHERE id = $1 RETURNING *',
    [t.id, kind, req.user.username, amount, notes, Date.now()]);
  return { t: u.rows[0], act: { owner: other, action: 'tr_req', row: { kind, amount: kind === 'edit' ? amount : t.amount, notes: t.notes }, prev: kind === 'edit' ? t.amount : null } };
})));
app.post('/api/transfers/:id/request/:answer', auth, noAdmin(TRANSFER_USERS), wrap((req, res) => onTransfer(req, res, async (c, t, other) => {
  const a = req.params.answer;
  if (!t.req_kind) return { code: 409, error: 'There is no request waiting' };
  if (!['agree', 'refuse', 'withdraw'].includes(a)) return { code: 404, error: 'Not found' };
  if ((a === 'withdraw') !== (t.req_by === req.user.username)) return { code: 403, error: a === 'withdraw' ? 'Only the person who asked can withdraw it' : 'You cannot answer your own request' };
  const clear = () => c.query('UPDATE transfers SET req_kind = NULL, req_by = NULL, req_amount = NULL, req_notes = NULL, req_ts = NULL WHERE id = $1 RETURNING *', [t.id]);
  const info = { kind: t.req_kind, amount: t.req_kind === 'edit' ? t.req_amount : t.amount, notes: t.notes };
  if (a !== 'agree') return { t: (await clear()).rows[0], act: { owner: other, action: a === 'refuse' ? 'tr_req_refuse' : 'tr_req_withdraw', row: info } };
  const acts = [{ owner: t.req_by, action: 'tr_req_agree', row: info }];
  if (t.req_kind === 'edit') await changeTransfer(c, t.id, req.user.username, Number(t.req_amount), t.req_notes || '');
  else await removeTransfer(c, t.id, req.user.username);
  return { t: (await c.query('SELECT * FROM transfers WHERE id = $1', [t.id])).rows[0], acts };
})));

// Parties (customers, suppliers, staff). A user's parties are private: only they can change them.
// Common parties are added by the admin, shared by everyone, and only the admin can change them.
// A private party may have the same name as a common one; they stay separate.
function parseParty(b) {
  const name = String(b.name || '').trim().slice(0, 80), phone = String(b.phone || '').replace(/[^\d+ ]/g, '').trim().slice(0, 20);
  const kind = ['customer', 'supplier', 'staff', 'other'].includes(b.kind) ? b.kind : 'customer';
  // Optional payment due date (YYYY-MM-DD); empty clears it.
  const due = validDate(b.due) ? b.due : '';
  if (!name) return { error: 'Enter a name' };
  return { v: { name, phone, kind, due } };
}
// The parties the caller may change: the admin its common parties, a user their private ones.
const editable = (req) => req.user.role === 'admin' ? ['common', []] : ['owner = $X AND NOT common', [req.user.username]];
async function dupName(req, name, id) {
  const [w, a] = editable(req);
  const q = await pool.query('SELECT 1 FROM parties WHERE ' + w.replace('$X', '$2') + ' AND lower(name) = lower($1)' + (id ? ' AND id <> $' + (a.length + 2) : ''),
    [name, ...a, ...(id ? [id] : [])]);
  return q.rowCount > 0;
}
app.post('/api/parties', auth, wrap(async (req, res) => {
  const p = parseParty(req.body), common = req.user.role === 'admin';
  if (p.error) return res.status(400).json({ error: p.error });
  if (await dupName(req, p.v.name)) return res.status(409).json({ error: common ? 'There is already a common party with that name' : 'You already have a party with that name' });
  const { rows } = await pool.query('INSERT INTO parties (id, owner, name, phone, kind, due, common, ts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [crypto.randomUUID(), req.user.username, p.v.name, p.v.phone, p.v.kind, p.v.due, common, Date.now()]);
  res.json(rowParty(rows[0]));
}));
app.put('/api/parties/:id', auth, wrap(async (req, res) => {
  const p = parseParty(req.body), [w, a] = editable(req);
  if (p.error) return res.status(400).json({ error: p.error });
  if (await dupName(req, p.v.name, req.params.id)) return res.status(409).json({ error: req.user.role === 'admin' ? 'There is already a common party with that name' : 'You already have a party with that name' });
  const { rows } = await pool.query('UPDATE parties SET name = $2, phone = $3, kind = $4, due = $5 WHERE id = $1 AND ' + w.replace('$X', '$6') + ' RETURNING *',
    [req.params.id, p.v.name, p.v.phone, p.v.kind, p.v.due, ...a]);
  if (!rows.length) return res.status(404).json({ error: 'Party not found' });
  res.json(rowParty(rows[0]));
}));
app.delete('/api/parties/:id', auth, wrap(async (req, res) => {
  const [w, a] = editable(req);
  const mine = await pool.query('SELECT 1 FROM parties WHERE id = $1 AND ' + w.replace('$X', '$2'), [req.params.id, ...a]);
  if (!mine.rowCount) return res.status(404).json({ error: 'Party not found' });
  const used = await pool.query('SELECT 1 FROM tx WHERE party_id = $1 LIMIT 1', [req.params.id]);
  if (used.rowCount) return res.status(409).json({ error: 'This party has entries. Delete those entries first.' });
  await pool.query('DELETE FROM parties WHERE id = $1', [req.params.id]);
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
