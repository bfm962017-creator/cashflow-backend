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
app.use(express.json({ limit: '50kb' }));
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
});
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
  const { rows } = await pool.query('SELECT username, role FROM users WHERE username = $1', [p.sub]);
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

app.get('/api/data', auth, wrap(async (req, res) => {
  const admin = req.user.role === 'admin';
  const t = admin
    ? await pool.query('SELECT * FROM tx ORDER BY tx_date, tx_time, ts')
    : await pool.query('SELECT * FROM tx WHERE username = $1 ORDER BY tx_date, tx_time, ts', [req.user.username]);
  const users = {};
  if (admin) {
    (await pool.query('SELECT username, role FROM users ORDER BY username')).rows
      .forEach((r) => { users[r.username] = { name: r.username, role: r.role }; });
  } else {
    users[req.user.username] = { name: req.user.username, role: req.user.role };
  }
  res.json({ me: { name: req.user.username, role: req.user.role }, users, txs: t.rows.map(rowTx) });
}));

function parseTx(b) {
  const type = b.type, amount = Math.round(Number(b.amount) * 100) / 100;
  const date = String(b.date || ''), time = String(b.time || '');
  const notes = String(b.notes || '').trim().slice(0, 500), desc = String(b.desc || '').trim().slice(0, 500);
  if (type !== 'in' && type !== 'out') return { error: 'Invalid type' };
  if (!(amount > 0 && amount < 1e11)) return { error: 'Enter a valid amount' };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(Date.parse(date))) return { error: 'Invalid date' };
  if (time && !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return { error: 'Invalid time' };
  return { v: { type, amount, date, time, notes, desc } };
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
  const { rows } = await pool.query(
    'INSERT INTO tx (id, username, kind, amount, tx_date, tx_time, notes, descr, ts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
    [id, owner, v.type, v.amount, v.date, v.time, v.notes, v.desc, Date.now()]);
  res.json(rowTx(rows[0]));
}));

app.put('/api/tx/:id', auth, wrap(async (req, res) => {
  const p = parseTx(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const cur = await pool.query('SELECT username FROM tx WHERE id = $1', [req.params.id]);
  if (!cur.rowCount || (req.user.role !== 'admin' && cur.rows[0].username !== req.user.username))
    return res.status(404).json({ error: 'Entry not found' });
  const v = p.v;
  const { rows } = await pool.query(
    'UPDATE tx SET kind=$2, amount=$3, tx_date=$4, tx_time=$5, notes=$6, descr=$7 WHERE id=$1 RETURNING *',
    [req.params.id, v.type, v.amount, v.date, v.time, v.notes, v.desc]);
  res.json(rowTx(rows[0]));
}));

app.delete('/api/tx/:id', auth, wrap(async (req, res) => {
  const r = req.user.role === 'admin'
    ? await pool.query('DELETE FROM tx WHERE id = $1', [req.params.id])
    : await pool.query('DELETE FROM tx WHERE id = $1 AND username = $2', [req.params.id, req.user.username]);
  if (!r.rowCount) return res.status(404).json({ error: 'Entry not found' });
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
  res.json({ ok: true });
}));

app.put('/api/users/:name/password', auth, adminOnly, wrap(async (req, res) => {
  const p = String(req.body.password || '');
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const r = await pool.query('UPDATE users SET pass_hash = $2 WHERE username = $1',
    [uname(req.params.name), await bcrypt.hash(p, 10)]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
}));

app.delete('/api/users/:name', auth, adminOnly, wrap(async (req, res) => {
  const r = await pool.query("DELETE FROM users WHERE username = $1 AND role <> 'admin'", [uname(req.params.name)]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found (admin cannot be deleted)' });
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.get('/', (req, res) => res.json({ name: 'cashflow-api', ok: true }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request' });
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
  app.listen(PORT, '0.0.0.0', () => console.log('Cashflow listening on ' + PORT));
})();
