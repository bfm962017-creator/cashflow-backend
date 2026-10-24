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

// Hosted databases (Render's external address, Supabase, Neon) need SSL; a local or private one does not.
// On Vercel each running copy of the server keeps only a couple of connections, so many copies
// together stay inside the database pooler's limit.
const pool = new Pool({
  connectionString: DB_URL,
  ssl: /\.render\.com|supabase\.(co|com)|neon\.tech|sslmode=require/.test(DB_URL) ? { rejectUnauthorized: false } : undefined,
  max: process.env.VERCEL ? 2 : 10,
  idleTimeoutMillis: process.env.VERCEL ? 5000 : 10000,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS login_fails (k TEXT PRIMARY KEY, n INT NOT NULL, t BIGINT NOT NULL);
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
ALTER TABLE users ADD COLUMN IF NOT EXISTS tok_after BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS drive_url TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS drive_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS drive_keep INT NOT NULL DEFAULT 90;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS drive_last TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS drive_err TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS drive_log (id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL, ok BOOLEAN NOT NULL, bytes INT NOT NULL DEFAULT 0, msg TEXT NOT NULL DEFAULT '');
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
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_to TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_from TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_key TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_summary BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_backup BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_last TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS mail_err TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS cron_key TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS vapid_pub TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS vapid_priv TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS push_prefs JSONB;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS remind_last TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS push_subs (
  endpoint TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  lang TEXT NOT NULL DEFAULT 'en',
  ts BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS push_subs_user_idx ON push_subs (username);
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
ALTER TABLE parties ADD COLUMN IF NOT EXISTS share_token TEXT;
ALTER TABLE parties ADD COLUMN IF NOT EXISTS share_notes BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE parties ADD COLUMN IF NOT EXISTS share_views INT NOT NULL DEFAULT 0;
ALTER TABLE parties ADD COLUMN IF NOT EXISTS share_seen BIGINT;
CREATE UNIQUE INDEX IF NOT EXISTS parties_share_idx ON parties (share_token);
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
-- Only this server reads the tables. On Supabase the public schema is also reachable through its
-- web API with a public key, so row security is switched on (with no policies that means no access)
-- and those web roles lose their rights. The server owns the tables, so this does not affect it.
DO $$ DECLARE t text; BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated';
  END IF;
END $$;
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
// The bump happens before the reply goes out: on Vercel the server may be paused as soon as it has replied.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'OPTIONS' && !/^\/(login|activity\/seen)$/.test(req.path)) {
    const send = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode >= 400) return send(body);
      pool.query('UPDATE meta SET rev = rev + 1 WHERE id = 1').catch(() => {}).then(() => send(body));
      return res;
    };
  }
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
const rowParty = (r) => ({ id: r.id, owner: r.owner, name: r.name, phone: r.phone, kind: r.kind, due: r.due || '', common: !!r.common, ts: Number(r.ts),
  share: r.share_token ? { token: r.share_token, notes: !!r.share_notes, views: Number(r.share_views), seen: r.share_seen == null ? null : Number(r.share_seen) } : null });
const rowAct = (r) => ({
  id: Number(r.id), ts: Number(r.ts), actor: r.actor, owner: r.owner, action: r.action, type: r.kind,
  amount: r.amount == null ? null : Number(r.amount), prev: r.prev_amount == null ? null : Number(r.prev_amount), notes: r.notes,
});
// Records who did what for the notification feed. A failed write never fails the request itself.
// action: lock | tr_req | tr_req_agree | tr_req_refuse | tr_req_withdraw | tx_add | tx_edit | tx_delete | tx_restore | user_add | user_delete | user_password | user_rename | drive_fail | settings | tr_send | tr_accept | tr_reject | tr_cancel
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
// Work that may finish after the reply (push notifications), so saving never waits for the push services.
// On Vercel, waitUntil keeps the function alive until it is done; elsewhere it simply runs on.
let waitUntil = null;
try { if (process.env.VERCEL) waitUntil = require('@vercel/functions').waitUntil; } catch (e) { /* not on Vercel */ }
const later = (p) => { if (waitUntil) waitUntil(p); else p.catch(() => {}); };
async function logAct(actor, owner, action, tx, prev) {
  try {
    await pool.query(
      'INSERT INTO activity (ts, actor, owner, action, kind, amount, prev_amount, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [Date.now(), actor, owner, action, tx ? tx.kind : null, tx ? tx.amount : null, prev == null ? null : prev, tx ? (tx.notes || tx.descr || '') : '']);
  } catch (e) { console.error('activity log failed:', e.message); }
  later(pushActivity({ actor, owner, action, kind: tx ? tx.kind : null, amount: tx ? tx.amount : null, prev, notes: tx ? (tx.notes || tx.descr || '') : '' }));
}
// ---- Push notifications (Web Push) ----
// Each phone that turns them on stores a subscription here. A push goes to the people who would see
// the activity under their bell: the user whose cashbook it is, and the admin (for the kinds the admin
// chose in Push settings). The person who did it never gets their own push.
// The VAPID key pair is made once and kept in settings, so nothing needs to be configured by hand.
const webpush = require('web-push');
const PUSH_DEFAULTS = { entries: true, changes: true, transfers: false, security: true, remind: true, overdue: true };
let vapid = null;
async function pushKeys() {
  if (vapid) return vapid;
  let r = (await pool.query('SELECT vapid_pub, vapid_priv FROM settings WHERE id = 1')).rows[0];
  if (!r.vapid_pub) {
    const k = webpush.generateVAPIDKeys();
    await pool.query("UPDATE settings SET vapid_pub = $1, vapid_priv = $2 WHERE id = 1 AND vapid_pub = ''", [k.publicKey, k.privateKey]);
    r = (await pool.query('SELECT vapid_pub, vapid_priv FROM settings WHERE id = 1')).rows[0];
  }
  vapid = { pub: r.vapid_pub, priv: r.vapid_priv };
  return vapid;
}
async function pushPrefs() {
  const r = (await pool.query('SELECT push_prefs FROM settings WHERE id = 1')).rows[0];
  return { ...PUSH_DEFAULTS, ...(r && r.push_prefs ? r.push_prefs : {}) };
}
// Sends one message to each subscription; ones the push service says are gone are removed.
// Activity pushes run after the reply (see later()); the test and the daily reminders wait for them.
async function sendPush(subs, make) {
  if (!subs.length) return 0;
  const k = await pushKeys(), subject = (ORIGINS[0] && /^https:/.test(ORIGINS[0])) ? ORIGINS[0] : 'mailto:noreply@cashflow.app';
  let sent = 0;
  await Promise.allSettled(subs.map(async (s) => {
    const msg = make(s.lang || 'en', s);
    if (!msg) return;
    try {
      await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(msg),
        { vapidDetails: { subject, publicKey: k.pub, privateKey: k.priv }, TTL: 12 * 3600, timeout: 4000, urgency: msg.urgent ? 'high' : 'normal' });
      sent++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) await pool.query('DELETE FROM push_subs WHERE endpoint = $1', [s.endpoint]).catch(() => {});
      else console.error('push failed:', e.statusCode || '', e.message);
    }
  }));
  return sent;
}
// Push wording in the language the phone uses (English, Hindi or Hinglish).
const PT = {
  en: { in: 'Cash In', out: 'Cash Out', added: 'added', changed: 'changed', edited: 'edited', deleted: 'deleted', restored: 'restored',
    sent: 'sent you', tap: 'tap to accept', accepted: 'accepted your transfer of', rejected: 'rejected your transfer of', cancelled: 'cancelled the transfer of',
    askEdit: 'asks to change the transfer', askDel: 'asks to delete the transfer of', agreed: 'agreed to your request', refused: 'refused your request', withdrew: 'withdrew the request',
    userAdd: 'New user added:', userDel: 'User removed:', userPw: 'Password changed for', userRen: 'Username changed:', driveFail: 'Google Drive backup failed:', settings: 'Business settings were changed', lockOff: 'Lock old entries turned off', lockOn: 'Lock old entries set to',
    days: 'days', blocked: 'wrong passwords for', blocked2: 'login blocked for 15 minutes', noEntry: 'No entries today', noEntry2: 'You have not added any entries today. Add them before you forget.',
    overdue: 'Overdue', late: 'days late', parties: 'parties' },
  hi: { in: 'नकद आया', out: 'नकद गया', added: 'ने जोड़ा', changed: 'ने बदला', edited: 'ने बदला', deleted: 'ने हटाया', restored: 'ने वापस लाया',
    sent: 'ने आपको भेजे', tap: 'स्वीकार करने के लिए टैप करें', accepted: 'ने आपका ट्रांसफ़र स्वीकार किया', rejected: 'ने आपका ट्रांसफ़र अस्वीकार किया', cancelled: 'ने ट्रांसफ़र रद्द किया',
    askEdit: 'ट्रांसफ़र बदलना चाहते हैं', askDel: 'ट्रांसफ़र हटाना चाहते हैं', agreed: 'ने आपकी बात मान ली', refused: 'ने आपकी बात नहीं मानी', withdrew: 'ने अनुरोध वापस लिया',
    userAdd: 'नया यूज़र जोड़ा गया:', userDel: 'यूज़र हटाया गया:', userPw: 'पासवर्ड बदला गया:', userRen: 'यूज़रनेम बदला गया:', driveFail: 'Google Drive बैकअप नहीं हुआ:', settings: 'बिज़नेस सेटिंग बदली गई', lockOff: 'पुरानी एंट्री लॉक बंद', lockOn: 'पुरानी एंट्री लॉक:',
    days: 'दिन', blocked: 'गलत पासवर्ड:', blocked2: '15 मिनट के लिए लॉगिन बंद', noEntry: 'आज कोई एंट्री नहीं', noEntry2: 'आपने आज कोई एंट्री नहीं जोड़ी। भूलने से पहले जोड़ लें।',
    overdue: 'बकाया', late: 'दिन लेट', parties: 'पार्टी' },
  hg: { in: 'Paisa Aaya', out: 'Paisa Gaya', added: 'ne joda', changed: 'ne badla', edited: 'ne badla', deleted: 'ne delete kiya', restored: 'ne wapas laya',
    sent: 'ne aapko bheje', tap: 'accept karne ke liye tap karein', accepted: 'ne aapka transfer accept kiya', rejected: 'ne aapka transfer reject kiya', cancelled: 'ne transfer cancel kiya',
    askEdit: 'transfer badalna chahte hain', askDel: 'transfer delete karna chahte hain', agreed: 'ne aapki baat maan li', refused: 'ne aapki baat nahi maani', withdrew: 'ne request wapas li',
    userAdd: 'Naya user joda:', userDel: 'User hataya:', userPw: 'Password badla:', userRen: 'Username badla:', driveFail: 'Google Drive backup nahi hua:', settings: 'Business settings badli gayi', lockOff: 'Purani entry lock band', lockOn: 'Purani entry lock:',
    days: 'din', blocked: 'galat password:', blocked2: '15 minute ke liye login band', noEntry: 'Aaj koi entry nahi', noEntry2: 'Aapne aaj koi entry nahi jodi. Bhoolne se pehle jod lein.',
    overdue: 'Overdue', late: 'din late', parties: 'party' },
};
const pr = (n) => '₹' + Math.abs(Number(n)).toLocaleString('en-IN', { maximumFractionDigits: 2 });
// Which admin switch an activity falls under (null: the admin is not sent it).
const PUSH_CAT = { tx_add: 'entries', tx_edit: 'changes', tx_delete: 'changes', tx_restore: 'changes', tr_send: 'transfers', tr_accept: 'transfers', tr_reject: 'transfers',
  tr_cancel: 'transfers', tr_req: 'transfers', tr_req_agree: 'transfers', tr_req_refuse: 'transfers', tr_req_withdraw: 'transfers',
  user_add: 'security', user_delete: 'security', user_password: 'security', user_rename: 'security', drive_fail: 'security', settings: 'security', lock: 'security', login_block: 'security' };
function pushMsg(lang, a, forOwner) {
  const t = PT[lang] || PT.en, k = a.kind === 'in' ? t.in : t.out, amt = a.amount == null ? '' : pr(a.amount), who = a.actor, note = a.notes ? ' · ' + a.notes : '';
  // Hindi puts the verb after the name; English and Hinglish read "<name> <verb>".
  const v = (verb, rest) => who + ' ' + verb + (rest ? ' ' + rest : '');
  const own = forOwner || a.owner === a.actor ? '' : ' (' + a.owner + ')';
  switch (a.action) {
    case 'tx_add': return { body: v(t.added, k + ' ' + amt) + own + note, go: 'tx' };
    case 'tx_edit': return { body: v(t.changed, (a.prev != null && Number(a.prev) !== Number(a.amount) ? pr(a.prev) + ' → ' : '') + amt) + own + note, go: 'tx' };
    case 'tx_delete': return { body: v(t.deleted, k + ' ' + amt) + own + note, go: 'tx' };
    case 'tx_restore': return { body: v(t.restored, k + ' ' + amt) + own + note, go: 'tx' };
    case 'tr_send': return forOwner ? { body: v(t.sent, amt) + note + ' · ' + t.tap, go: 'transfer', urgent: true } : { body: who + ' → ' + a.owner + ' ' + amt + note, go: 'transfer' };
    case 'tr_accept': return { body: v(t.accepted, amt) + (forOwner ? '' : own), go: 'transfer' };
    case 'tr_reject': return { body: v(t.rejected, amt) + (forOwner ? '' : own), go: 'transfer' };
    case 'tr_cancel': return { body: v(t.cancelled, amt) + (forOwner ? '' : own), go: 'transfer' };
    case 'tr_req': return { body: who + ' ' + (a.kind === 'edit' ? t.askEdit + (a.prev != null ? ' ' + pr(a.prev) + ' → ' : ' ') + amt : t.askDel + ' ' + amt) + (forOwner ? '' : own), go: 'transfer', urgent: forOwner };
    case 'tr_req_agree': return { body: v(t.agreed) + (forOwner ? '' : own), go: 'transfer' };
    case 'tr_req_refuse': return { body: v(t.refused) + (forOwner ? '' : own), go: 'transfer' };
    case 'tr_req_withdraw': return { body: v(t.withdrew) + (forOwner ? '' : own), go: 'transfer' };
    case 'user_add': return { body: t.userAdd + ' ' + a.owner, go: 'bell' };
    case 'user_delete': return { body: t.userDel + ' ' + a.owner, go: 'bell' };
    case 'user_password': return { body: t.userPw + ' ' + a.owner, go: 'bell' };
    case 'user_rename': return { body: t.userRen + ' ' + a.notes + ' → ' + a.owner, go: 'bell' };
    case 'drive_fail': return { title: '☁️ Google Drive', body: t.driveFail + ' ' + a.notes, go: 'bell', urgent: true };
    case 'settings': return { body: t.settings + ' (' + who + ')', go: 'bell' };
    case 'lock': return { body: Number(a.amount) < 0 ? t.lockOff : t.lockOn + ' ' + Number(a.amount) + ' ' + t.days, go: 'bell' };
    case 'login_block': return { title: '⚠️ ' + (lang === 'en' ? 'Security' : lang === 'hi' ? 'सुरक्षा' : 'Security'), body: '8 ' + t.blocked + ' ' + a.owner + ' · ' + t.blocked2, go: 'bell', urgent: true };
    default: return null;
  }
}
async function pushActivity(a) {
  try {
    const { rows } = await pool.query(
      `SELECT s.*, u.role FROM push_subs s JOIN users u ON u.username = s.username WHERE s.username = $1 OR u.role = 'admin'`, [a.owner]);
    if (!rows.length) return;
    const prefs = await pushPrefs(), biz = (await pool.query('SELECT name FROM settings WHERE id = 1')).rows[0].name || 'Cashflow';
    const subs = rows.filter((s) => s.username !== a.actor && (s.username === a.owner || (s.role === 'admin' && prefs[PUSH_CAT[a.action]])));
    await sendPush(subs, (lang, s) => {
      const m = pushMsg(lang, a, s.username === a.owner);
      return m && { title: m.title || biz, body: m.body.slice(0, 240), go: m.go, urgent: !!m.urgent, tag: a.action.startsWith('tr_') ? 'tr' : undefined };
    });
  } catch (e) { console.error('push activity failed:', e.message); }
}

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

// Login throttle: 8 failures / 15 min per ip+username. Kept in the database, because on Vercel
// several copies of the server run side by side and none of them remembers anything between requests.
const WINDOW = 15 * 60 * 1000;
const limited = async (k) => {
  const r = (await pool.query('SELECT n, t FROM login_fails WHERE k = $1', [k])).rows[0];
  return !!r && r.n >= 8 && Date.now() - Number(r.t) < WINDOW;
};
const addFail = async (k) => {
  const now = Date.now();
  const r = await pool.query(`INSERT INTO login_fails (k, n, t) VALUES ($1, 1, $2) ON CONFLICT (k) DO UPDATE
    SET n = CASE WHEN $2 - login_fails.t > ${WINDOW} THEN 1 ELSE login_fails.n + 1 END, t = $2 RETURNING n`, [k, now]);
  await pool.query('DELETE FROM login_fails WHERE t < $1', [now - WINDOW]);
  return r.rows[0].n;
};

const auth = wrap(async (req, res, next) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return res.status(401).json({ error: 'Not signed in' });
  let p;
  try { p = jwt.verify(m[1], SECRET, { algorithms: ['HS256'] }); }
  catch { return res.status(401).json({ error: 'Session expired' }); }
  const { rows } = await pool.query('SELECT username, role, seen_at, tok_after, full_name FROM users WHERE username = $1', [p.sub]);
  if (!rows.length) return res.status(401).json({ error: 'Account no longer exists' });
  // tok_after (seconds) moves forward when the password changes or the account is created again,
  // so sign-ins from before that stop working.
  if (!(p.iat >= Number(rows[0].tok_after))) return res.status(401).json({ error: 'Please sign in again' });
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
  if (await limited(key)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { rows } = await pool.query('SELECT username, pass_hash FROM users WHERE username = $1', [u]);
  const ok = await bcrypt.compare(p, rows.length ? rows[0].pass_hash : DUMMY_HASH);
  if (!rows.length || !ok) {
    // The 8th wrong password for an existing user locks the login and warns the admin (and the user).
    if ((await addFail(key)) === 8 && rows.length) await logAct('system', u, 'login_block');
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  await pool.query('DELETE FROM login_fails WHERE k = $1', [key]);
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
    (await pool.query('SELECT username, role, full_name FROM users ORDER BY username')).rows
      .forEach((r) => { users[r.username] = { name: r.username, role: r.role, full: r.full_name }; });
  } else {
    users[req.user.username] = { name: req.user.username, role: req.user.role, full: req.user.full_name };
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
// User report (admin): how many entries in each user's book were edited or deleted between two times (ms).
app.get('/api/report/changes', auth, adminOnly, wrap(async (req, res) => {
  const from = Number(req.query.from), to = Number(req.query.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) return res.status(400).json({ error: 'Invalid date range' });
  const { rows } = await pool.query(
    `SELECT owner, action, COUNT(DISTINCT tx_id)::int AS n FROM tx_history
     WHERE action IN ('edit','delete') AND ts >= $1 AND ts < $2 GROUP BY owner, action`, [from, to]);
  const out = {};
  rows.forEach((r) => { (out[r.owner] = out[r.owner] || { edit: 0, delete: 0 })[r.action] = r.n; });
  res.json(out);
}));
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
  if (s.transfer_id && req.user.role !== 'admin') return res.status(403).json({ error: 'Only the admin can restore a transfer' });
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
    let made = [];
    try { made = fn ? await fn(c, t) : []; }
    catch (e) {
      if (e.message !== 'LOCKED') throw e;
      await c.query('ROLLBACK');
      return res.status(403).json({ error: 'This transfer is dated ' + +t.tx_date.slice(8) + ' ' + MON[+t.tx_date.slice(5, 7) - 1] + ', before the lock date. Ask ' + t.from_user + ' to cancel it and send it again with a newer date.' });
    }
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
  const cut = await lockCutoff(req);
  await decide(req, res, 'to_user', 'accepted', async (c, t) => {
    // The lock may have moved past the transfer's date while it was waiting.
    if (cut && t.tx_date < cut) { const e = new Error('LOCKED'); e.cut = cut; throw e; }
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
  const cut = await lockCutoff(req);
  if (cut && t.tx_date < cut) return { code: 403, error: 'Locked: entries before ' + +cut.slice(8) + ' ' + MON[+cut.slice(5, 7) - 1] + ' ' + cut.slice(0, 4) + ' can only be changed by the admin' };
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

// Customer khata link: a secret read-only link to one party's statement, opened without signing in.
// The party's owner (or the admin, for a common party) turns it on, off, or replaces it.
const newToken = () => crypto.randomBytes(12).toString('base64url');
async function shareEdit(req, res, sql, params) {
  const [w, a] = editable(req);
  const { rows } = await pool.query('UPDATE parties SET ' + sql + ' WHERE id = $1 AND ' + w.replace('$X', '$' + (params.length + 2)) + ' RETURNING *', [req.params.id, ...params, ...a]);
  if (!rows.length) return res.status(404).json({ error: 'Party not found' });
  res.json(rowParty(rows[0]));
}
app.post('/api/parties/:id/share', auth, wrap((req, res) =>
  shareEdit(req, res, 'share_token = COALESCE(share_token, $2), share_notes = $3', [newToken(), req.body.notes !== false])));
app.post('/api/parties/:id/share/reset', auth, wrap((req, res) =>
  shareEdit(req, res, 'share_token = $2, share_views = 0, share_seen = NULL', [newToken()])));
app.put('/api/parties/:id/share', auth, wrap((req, res) => shareEdit(req, res, 'share_notes = $2', [req.body.notes !== false])));
app.delete('/api/parties/:id/share', auth, wrap((req, res) =>
  shareEdit(req, res, 'share_token = NULL, share_views = 0, share_seen = NULL', [])));
// Public: only this party's entries, with no user names, ids or photos.
app.get('/api/k/:token', wrap(async (req, res) => {
  const t = String(req.params.token || '');
  if (!/^[A-Za-z0-9_-]{16}$/.test(t)) return res.status(404).json({ error: 'This link is not valid or was turned off' });
  const { rows } = await pool.query('UPDATE parties SET share_views = share_views + 1, share_seen = $2 WHERE share_token = $1 RETURNING *', [t, Date.now()]);
  if (!rows.length) return res.status(404).json({ error: 'This link is not valid or was turned off' });
  const p = rows[0];
  const tx = p.common
    ? await pool.query('SELECT * FROM tx WHERE party_id = $1 ORDER BY tx_date, tx_time, ts', [p.id])
    : await pool.query('SELECT * FROM tx WHERE party_id = $1 AND username = $2 ORDER BY tx_date, tx_time, ts', [p.id, p.owner]);
  const b = await bizInfo(true);
  res.set('Cache-Control', 'no-store').json({
    biz: { name: b.name, address: b.address, logo: b.logo },
    party: { name: p.name, kind: p.kind, due: p.due || '' }, notes: !!p.share_notes,
    entries: tx.rows.map((x) => ({ date: x.tx_date, type: x.kind, amount: Number(x.amount),
      notes: p.share_notes ? x.notes : '', desc: p.share_notes ? x.descr : '' })),
  });
}));

// ---- Email reports (Brevo): nightly summary and Excel backup to the admin ----
// The Brevo API key comes from BREVO_API_KEY or is pasted by the admin in the app (stored here, never sent back).
// Sleeping free servers have no reliable timer, so an outside scheduler (e.g. cron-job.org) opens
// /api/cron/daily?key=<secret> each night; it sends at most once per India day unless forced.
const ExcelJS = require('exceljs');
const BREVO_URL = process.env.BREVO_URL || 'https://api.brevo.com/v3/smtp/email';
const MON_S = MON;
const fmtR = (n) => (n < 0 ? '−' : '') + '₹' + Math.abs(Number(n)).toLocaleString('en-IN', { maximumFractionDigits: 2 });
const dLabel = (d) => +d.slice(8) + ' ' + MON_S[+d.slice(5, 7) - 1] + ' ' + d.slice(0, 4);
const escH = (x) => String(x == null ? '' : x).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
async function mailCfg() {
  const r = (await pool.query('SELECT * FROM settings WHERE id = 1')).rows[0];
  if (!r.cron_key) { r.cron_key = newToken() + newToken(); await pool.query('UPDATE settings SET cron_key = $1 WHERE id = 1', [r.cron_key]); }
  return { ...r, key: process.env.BREVO_API_KEY || r.mail_key, keyFromEnv: !!process.env.BREVO_API_KEY };
}
async function sendMail(c, subject, html, attachments) {
  if (!c.key) throw new Error('Add your Brevo API key first');
  if (!c.mail_to) throw new Error('Enter the email address to send to');
  const r = await fetch(BREVO_URL, { method: 'POST', headers: { 'api-key': c.key, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: c.name || 'Cashflow', email: c.mail_from || c.mail_to }, to: [{ email: c.mail_to }], subject, htmlContent: html,
      ...(attachments && attachments.length ? { attachment: attachments } : {}) }) });
  if (!r.ok) { let m = ''; try { m = (await r.json()).message || ''; } catch {} throw new Error('Brevo did not accept the email' + (m ? ': ' + m : ' (' + r.status + ')')); }
}
// Everything the summary and the backup need, worked out on the server.
async function reportData() {
  const today = istToday(), mo = today.slice(0, 7);
  const [tx, parties, users, trs] = await Promise.all([
    pool.query('SELECT * FROM tx ORDER BY tx_date, tx_time, ts'), pool.query('SELECT * FROM parties ORDER BY lower(name)'),
    pool.query('SELECT username, role FROM users ORDER BY username'), pool.query("SELECT * FROM transfers WHERE status = 'pending' OR req_kind IS NOT NULL")]);
  const r2 = (n) => Math.round(n * 100) / 100, sum = (f) => { let i = 0, o = 0, n = 0; tx.rows.forEach((t) => { if (!f(t)) return; n++; t.kind === 'in' ? i = r2(i + Number(t.amount)) : o = r2(o + Number(t.amount)); }); return { i, o, n }; };
  const day = sum((t) => t.tx_date === today && !t.transfer_id), month = sum((t) => t.tx_date.startsWith(mo) && !t.transfer_id), all = sum(() => true);
  const perUser = users.rows.filter((u) => u.role === 'user').map((u) => ({ name: u.username, today: sum((t) => t.username === u.username && t.tx_date === today), bal: (() => { const x = sum((t) => t.username === u.username); return r2(x.i - x.o); })() }));
  const pbal = (p) => { let b = 0; tx.rows.forEach((t) => { if (t.party_id === p.id && (p.common || t.username === p.owner)) b = r2(b + (t.kind === 'out' ? 1 : -1) * Number(t.amount)); }); return b; };
  const plist = parties.rows.map((p) => ({ p, bal: pbal(p) }));
  const overdue = plist.filter((x) => x.p.due && x.bal > 0 && x.p.due < today).map((x) => ({ name: x.p.name, owner: x.p.common ? 'Common' : x.p.owner, bal: x.bal, due: x.p.due,
    late: Math.round((Date.parse(today) - Date.parse(x.p.due)) / 864e5) })).sort((a, b) => b.late - a.late);
  return { today, day, month, all, perUser, overdue, plist, tx: tx.rows, users: users.rows, parties: parties.rows, waiting: trs.rowCount };
}
function summaryHtml(c, d) {
  const td = 'style="padding:6px 10px;border-bottom:1px solid #e5e7eb"', tr = (a, b) => `<tr><td ${td}>${a}</td><td ${td} align="right">${b}</td></tr>`;
  let h = `<div style="font-family:Arial,sans-serif;max-width:560px;color:#1b1f24"><div style="background:#0f766e;color:#fff;padding:14px 16px;border-radius:10px 10px 0 0"><b style="font-size:18px">${escH(c.name || 'Cashflow')}</b><br><span style="opacity:.85">Daily summary · ${dLabel(d.today)}</span></div><div style="border:1px solid #e5e7eb;border-top:0;padding:14px 16px;border-radius:0 0 10px 10px">`;
  h += `<h3 style="margin:0 0 6px">Today</h3><table style="border-collapse:collapse;width:100%">${tr('Cash in', `<b style="color:#047857">${fmtR(d.day.i)}</b>`)}${tr('Cash out', `<b style="color:#b91c1c">${fmtR(d.day.o)}</b>`)}${tr('Net', `<b>${fmtR(d.day.i - d.day.o)}</b>`)}${tr('Entries', d.day.n)}</table>`;
  h += `<h3 style="margin:16px 0 6px">This month</h3><table style="border-collapse:collapse;width:100%">${tr('Cash in', fmtR(d.month.i))}${tr('Cash out', fmtR(d.month.o))}${tr('Net', fmtR(d.month.i - d.month.o))}</table>`;
  h += `<h3 style="margin:16px 0 6px">Users</h3><table style="border-collapse:collapse;width:100%"><tr><th align="left" ${td}>User</th><th align="right" ${td}>Today in / out</th><th align="right" ${td}>Balance</th></tr>` +
    d.perUser.map((u) => `<tr><td ${td}>${escH(u.name)}</td><td ${td} align="right">${fmtR(u.today.i)} / ${fmtR(u.today.o)}</td><td ${td} align="right"><b style="color:${u.bal < 0 ? '#b91c1c' : '#1b1f24'}">${fmtR(u.bal)}</b></td></tr>`).join('') + '</table>';
  h += `<h3 style="margin:16px 0 6px">Overdue parties ${d.overdue.length ? '(' + d.overdue.length + ')' : ''}</h3>` + (d.overdue.length ? `<table style="border-collapse:collapse;width:100%">` +
    d.overdue.map((o) => `<tr><td ${td}>${escH(o.name)} <span style="color:#6b7280">· ${escH(o.owner)}</span><br><small style="color:#b91c1c">due ${dLabel(o.due)} · ${o.late} days late</small></td><td ${td} align="right"><b style="color:#b91c1c">${fmtR(o.bal)}</b></td></tr>`).join('') + '</table>' : '<p style="color:#6b7280;margin:0">None 🎉</p>');
  if (d.waiting) h += `<p style="margin:14px 0 0;color:#b45309">⏳ ${d.waiting} transfer${d.waiting === 1 ? '' : 's'} waiting for a user's OK.</p>`;
  return h + `<p style="color:#6b7280;font-size:12px;margin:16px 0 0">Sent automatically by your Cashflow app.${c.mail_backup ? ' The full Excel backup is attached.' : ''}</p></div></div>`;
}
async function backupXlsx(c, d) {
  const wb = new ExcelJS.Workbook(), money = '#,##0.00;-#,##0.00', pn = {}; d.parties.forEach((p) => { pn[p.id] = p.name; });
  const sheet = (name, cols) => { const ws = wb.addWorksheet(name); ws.columns = cols.map(([header, key, width]) => ({ header, key, width })); const h = ws.getRow(1);
    h.font = { bold: true, color: { argb: 'FFFFFFFF' } }; h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F766E' } }; ws.views = [{ state: 'frozen', ySplit: 1 }]; return ws; };
  const sm = sheet('Summary', [['Item', 'k', 28], ['Value', 'v', 40]]);
  [['Business', c.name || ''], ['Backup date', dLabel(d.today)], ['Entries', d.tx.length], ['Total cash in', d.all.i], ['Total cash out', d.all.o], ['Balance', d.all.i - d.all.o], ['Parties', d.parties.length], ['Users', d.users.length]].forEach(([k, v]) => sm.addRow({ k, v }));
  const es = sheet('Entries', [['Date', 'date', 12], ['Time', 'time', 8], ['User', 'user', 12], ['Type', 'type', 10], ['Cash in', 'in', 13], ['Cash out', 'out', 13], ['Notes', 'notes', 30], ['Description', 'desc', 24], ['Party', 'party', 20], ['Transfer', 'tr', 9]]);
  d.tx.forEach((t) => es.addRow({ date: t.tx_date, time: t.tx_time, user: t.username, type: t.kind === 'in' ? 'Cash In' : 'Cash Out', in: t.kind === 'in' ? Number(t.amount) : null, out: t.kind === 'out' ? Number(t.amount) : null,
    notes: t.notes, desc: t.descr, party: t.party_id ? pn[t.party_id] || '' : '', tr: t.transfer_id ? 'Yes' : '' }));
  ['in', 'out'].forEach((k) => { es.getColumn(k).numFmt = money; });
  const ps = sheet('Parties', [['Name', 'name', 22], ['Owner', 'owner', 12], ['Type', 'kind', 10], ['Phone', 'phone', 14], ['Due date', 'due', 12], ['Balance (they owe +)', 'bal', 18]]);
  d.plist.forEach((x) => ps.addRow({ name: x.p.name, owner: x.p.common ? 'Common' : x.p.owner, kind: x.p.kind, phone: x.p.phone, due: x.p.due || '', bal: x.bal }));
  ps.getColumn('bal').numFmt = money;
  const us = sheet('Users', [['User', 'u', 14], ['Role', 'r', 8], ['Balance', 'b', 14]]);
  d.users.forEach((u) => { const x = d.perUser.find((p) => p.name === u.username); us.addRow({ u: u.username, r: u.role, b: x ? x.bal : null }); });
  us.getColumn('b').numFmt = money;
  return Buffer.from(await wb.xlsx.writeBuffer()).toString('base64');
}
async function sendReport(c) {
  const d = await reportData(), att = [];
  if (c.mail_backup) att.push({ name: 'Cashflow backup ' + d.today + '.xlsx', content: await backupXlsx(c, d) });
  await sendMail(c, (c.name || 'Cashflow') + ' · Daily summary · ' + dLabel(d.today), c.mail_summary ? summaryHtml(c, d) :
    `<p>${escH(c.name || 'Cashflow')} backup for ${dLabel(d.today)} is attached.</p>`, att);
  await pool.query("UPDATE settings SET mail_last = $1, mail_err = '' WHERE id = 1", [d.today + ' ' + new Date(Date.now() + 330 * 60000).toISOString().slice(11, 16)]);
}
const mailView = (c) => ({ to: c.mail_to, from: c.mail_from, summary: c.mail_summary, backup: c.mail_backup, hasKey: !!c.key, keyFromEnv: c.keyFromEnv,
  keyHint: c.key ? '••••' + c.key.slice(-4) : '', last: c.mail_last, err: c.mail_err, cronPath: '/api/cron/daily?key=' + c.cron_key });
const okEmail = (e) => e === '' || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
app.get('/api/mail', auth, adminOnly, wrap(async (req, res) => res.json(mailView(await mailCfg()))));
app.put('/api/mail', auth, adminOnly, wrap(async (req, res) => {
  const to = String(req.body.to || '').trim().slice(0, 200), from = String(req.body.from || '').trim().slice(0, 200);
  if (!okEmail(to) || !okEmail(from)) return res.status(400).json({ error: 'Enter a valid email address' });
  const key = req.body.key == null ? null : String(req.body.key).trim().slice(0, 300);
  await pool.query('UPDATE settings SET mail_to = $1, mail_from = $2, mail_summary = $3, mail_backup = $4' + (key != null ? ', mail_key = $5' : '') + ' WHERE id = 1',
    [to, from, req.body.summary !== false, req.body.backup !== false, ...(key != null ? [key] : [])]);
  res.json(mailView(await mailCfg()));
}));
app.post('/api/mail/test', auth, adminOnly, wrap(async (req, res) => {
  const c = await mailCfg();
  try { await sendMail(c, (c.name || 'Cashflow') + ' · Test email', `<p style="font-family:Arial">✅ Email is working. Your daily summary and backup will arrive at this address.</p>`); }
  catch (e) { return res.status(400).json({ error: e.message }); }
  res.json({ ok: true });
}));
app.post('/api/mail/send-now', auth, adminOnly, wrap(async (req, res) => {
  const c = await mailCfg();
  try { await sendReport(c); } catch (e) { await pool.query('UPDATE settings SET mail_err = $1 WHERE id = 1', [e.message.slice(0, 300)]); return res.status(400).json({ error: e.message }); }
  res.json(mailView(await mailCfg()));
}));
// ---- Google Drive backup ----
// The admin deploys a small Google Apps Script (web app) in their own Google account; each night the
// server posts the Excel backup to it and the script saves it in a "Cashflow Backups" folder in their
// Drive, deleting files older than the chosen number of days. The script only accepts our secret.
const XLSX_TYPE = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
const DRIVE_URL_RE = /^https:\/\/script\.google\.com\/(a\/[\w.-]+\/)?macros\/s\/[\w-]{20,200}\/exec$/;
const DRIVE_KEEP = [0, 30, 60, 90, 180, 365];
async function driveCfg() {
  const c = await mailCfg();
  if (!c.drive_secret) { c.drive_secret = newToken() + newToken(); await pool.query('UPDATE settings SET drive_secret = $1 WHERE id = 1', [c.drive_secret]); }
  return c;
}
const driveScript = (secret) => `// Cashflow → Google Drive backup.
// Paste this into a new project at script.google.com, then Deploy → New deployment → Web app
// (Execute as: Me, Who has access: Anyone) and copy the Web app link into the Cashflow app.
const SECRET = '${secret}';
const FOLDER = 'Cashflow Backups';

function doGet() {
  return out({ ok: true, app: 'cashflow-drive' });
}

function doPost(e) {
  let b;
  try { b = JSON.parse(e.postData.contents); } catch (x) { return out({ ok: false, error: 'Bad request' }); }
  if (b.secret !== SECRET) return out({ ok: false, error: 'Wrong secret' });
  const it = DriveApp.getFoldersByName(FOLDER), folder = it.hasNext() ? it.next() : DriveApp.createFolder(FOLDER);
  // A second backup on the same day replaces the first one.
  const same = folder.getFilesByName(b.name);
  while (same.hasNext()) same.next().setTrashed(true);
  const file = folder.createFile(Utilities.newBlob(Utilities.base64Decode(b.data), b.type, b.name));
  let removed = 0;
  const keep = Number(b.keep) || 0;
  if (keep > 0) {
    const cut = Date.now() - keep * 86400000, all = folder.getFiles();
    while (all.hasNext()) { const f = all.next(); if (f.getDateCreated().getTime() < cut) { f.setTrashed(true); removed++; } }
  }
  return out({ ok: true, size: file.getSize(), removed: removed, folder: folder.getUrl() });
}

function out(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}
`;
async function driveSend(c) {
  const d = await reportData(), data = await backupXlsx(c, d), name = 'Cashflow backup ' + d.today + '.xlsx';
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 45000);
  let j;
  try {
    const r = await fetch(c.drive_url, { method: 'POST', headers: { 'content-type': 'text/plain' }, redirect: 'follow', signal: ctl.signal,
      body: JSON.stringify({ secret: c.drive_secret, name, type: XLSX_TYPE, data, keep: c.drive_keep }) });
    const txt = await r.text();
    try { j = JSON.parse(txt); } catch (e) {
      throw new Error(r.ok ? 'Google did not answer as expected. Deploy the script as a Web app with access "Anyone".' : 'Google answered with error ' + r.status + '. Check the Drive link.');
    }
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Google Drive took too long to answer. Try again.');
    if (e.message && e.message.startsWith('fetch failed')) throw new Error('Could not reach Google Drive. Check the Drive link.');
    throw e;
  } finally { clearTimeout(timer); }
  if (!j.ok) throw new Error(j.error === 'Wrong secret' ? 'The script in Google has an old secret. Copy the script again, paste it and deploy a new version.' : j.error || 'Google Drive did not save the file');
  return { name, size: Number(j.size) || Math.round(data.length * 3 / 4), removed: Number(j.removed) || 0, folder: j.folder || '' };
}
// Runs one backup and records how it went. Returns the error message, or '' when it worked.
async function driveRun(c) {
  const now = Date.now(), stamp = istToday() + ' ' + new Date(now + 330 * 60000).toISOString().slice(11, 16);
  try {
    const r = await driveSend(c);
    await pool.query("UPDATE settings SET drive_last = $1, drive_err = '' WHERE id = 1", [stamp]);
    await pool.query('INSERT INTO drive_log (ts, ok, bytes, msg) VALUES ($1, true, $2, $3)', [now, r.size, r.folder]);
    return '';
  } catch (e) {
    const m = String(e.message || e).slice(0, 300);
    await pool.query('UPDATE settings SET drive_err = $1 WHERE id = 1', [m]);
    await pool.query('INSERT INTO drive_log (ts, ok, msg) VALUES ($1, false, $2)', [now, m]);
    return m;
  } finally {
    await pool.query('DELETE FROM drive_log WHERE id NOT IN (SELECT id FROM drive_log ORDER BY ts DESC LIMIT 30)');
  }
}
async function driveView(c) {
  const log = (await pool.query('SELECT ts, ok, bytes, msg FROM drive_log ORDER BY ts DESC LIMIT 10')).rows;
  const lastOk = log.find((x) => x.ok);
  return { url: c.drive_url, keep: c.drive_keep, last: c.drive_last, err: c.drive_err, script: driveScript(c.drive_secret),
    folder: lastOk ? lastOk.msg : '', log: log.map((x) => ({ ts: Number(x.ts), ok: x.ok, bytes: x.bytes, msg: x.ok ? '' : x.msg })) };
}
app.get('/api/drive', auth, adminOnly, wrap(async (req, res) => res.json(await driveView(await driveCfg()))));
app.put('/api/drive', auth, adminOnly, wrap(async (req, res) => {
  const url = String(req.body.url || '').trim(), keep = Number(req.body.keep);
  if (url && !DRIVE_URL_RE.test(url)) return res.status(400).json({ error: 'This is not a Google Apps Script Web app link. It starts with https://script.google.com/macros/s/ and ends with /exec' });
  if (!DRIVE_KEEP.includes(keep)) return res.status(400).json({ error: 'Choose how long to keep backups' });
  // Once connected, the link and how long backups are kept change only with the admin's password,
  // so a slip of the finger cannot stop the backups or delete old ones.
  const c = await driveCfg();
  if (c.drive_url && (url !== c.drive_url || keep !== c.drive_keep)) {
    const k = 'pw|' + req.user.username;
    if (await limited(k)) return res.status(429).json({ error: 'Too many wrong passwords. Try again in 15 minutes.' });
    const h = (await pool.query('SELECT pass_hash FROM users WHERE username = $1', [req.user.username])).rows[0];
    if (!req.body.password || !h || !(await bcrypt.compare(String(req.body.password), h.pass_hash))) {
      await addFail(k);
      return res.status(403).json({ error: req.body.password ? 'Wrong password' : 'Enter your password to change this' });
    }
    await pool.query('DELETE FROM login_fails WHERE k = $1', [k]);
  }
  await pool.query("UPDATE settings SET drive_url = $1, drive_keep = $2, drive_err = CASE WHEN drive_url = $1 THEN drive_err ELSE '' END WHERE id = 1", [url, keep]);
  res.json(await driveView(await driveCfg()));
}));
app.post('/api/drive/run', auth, adminOnly, wrap(async (req, res) => {
  const c = await driveCfg();
  if (!c.drive_url) return res.status(400).json({ error: 'Paste your Drive link first' });
  const e = await driveRun(c);
  if (e) return res.status(400).json({ error: e });
  res.json(await driveView(await driveCfg()));
}));

// Opened every night by Vercel Cron (or cron-job.org with ?key=). Sends the email report and the Drive
// backup, each at most once per India day; ?force=1 sends again.
app.get('/api/cron/daily', wrap(async (req, res) => {
  const c = await driveCfg();
  // Opened by cron-job.org with ?key=, or by Vercel Cron, which sends "Authorization: Bearer <CRON_SECRET>".
  const vercelCron = !!process.env.CRON_SECRET && req.headers.authorization === 'Bearer ' + process.env.CRON_SECRET;
  if (!vercelCron && (!req.query.key || String(req.query.key) !== c.cron_key)) return res.status(403).json({ error: 'Not allowed' });
  const today = istToday(), force = !!req.query.force, out = { ok: true };
  if (!c.mail_to || (!c.mail_summary && !c.mail_backup)) out.mail = 'off';
  else if (c.mail_last.startsWith(today) && !force) out.mail = 'already sent today';
  else {
    try { await sendReport(c); out.mail = 'sent'; }
    catch (e) { await pool.query('UPDATE settings SET mail_err = $1 WHERE id = 1', [e.message.slice(0, 300)]); out.mail = 'failed: ' + e.message; }
  }
  if (!c.drive_url) out.drive = 'off';
  else if (c.drive_last.startsWith(today) && !force) out.drive = 'already done today';
  else {
    const e = await driveRun(c);
    out.drive = e ? 'failed: ' + e : 'saved';
    if (e) {
      const a = (await pool.query("SELECT username FROM users WHERE role = 'admin' ORDER BY username LIMIT 1")).rows[0];
      if (a) await logAct('system', a.username, 'drive_fail', { kind: null, amount: null, notes: e });
    }
  }
  res.json(out);
}));

// ---- Push notification routes ----
app.get('/api/push/key', auth, wrap(async (req, res) => res.json({ key: (await pushKeys()).pub })));
app.post('/api/push/subscribe', auth, wrap(async (req, res) => {
  const s = req.body.sub || {}, k = s.keys || {}, lang = ['en', 'hi', 'hg'].includes(req.body.lang) ? req.body.lang : 'en';
  if (!/^https:\/\/[^\s]{10,900}$/.test(String(s.endpoint || '')) || !k.p256dh || !k.auth || String(k.p256dh).length > 200 || String(k.auth).length > 100)
    return res.status(400).json({ error: 'Bad subscription' });
  // One phone, one person: signing in as someone else on the same phone moves the subscription to them.
  await pool.query(`INSERT INTO push_subs (endpoint, username, p256dh, auth, lang, ts) VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (endpoint) DO UPDATE SET username = $2, p256dh = $3, auth = $4, lang = $5, ts = $6`,
    [s.endpoint, req.user.username, String(k.p256dh), String(k.auth), lang, Date.now()]);
  res.json({ ok: true });
}));
app.post('/api/push/unsubscribe', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM push_subs WHERE endpoint = $1 AND username = $2', [String(req.body.endpoint || ''), req.user.username]);
  res.json({ ok: true });
}));
app.post('/api/push/test', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM push_subs WHERE username = $1', [req.user.username]);
  const n = await sendPush(rows, (lang) => ({ title: '🔔 Cashflow', body: lang === 'hi' ? 'नोटिफ़िकेशन चालू हैं ✓' : lang === 'hg' ? 'Notifications chalu hain ✓' : 'Notifications are on ✓', go: 'tx' }));
  res.json({ sent: n, phones: rows.length });
}));
app.get('/api/push/prefs', auth, adminOnly, wrap(async (req, res) => res.json(await pushPrefs())));
app.put('/api/push/prefs', auth, adminOnly, wrap(async (req, res) => {
  const p = {};
  Object.keys(PUSH_DEFAULTS).forEach((k) => { p[k] = req.body[k] === undefined ? undefined : !!req.body[k]; });
  const cur = await pushPrefs(), next = {};
  Object.keys(PUSH_DEFAULTS).forEach((k) => { next[k] = p[k] === undefined ? cur[k] : p[k]; });
  await pool.query('UPDATE settings SET push_prefs = $1 WHERE id = 1', [next]);
  res.json(next);
}));
// Daily reminders (Vercel Cron at 8 PM India time, or cron-job.org with ?key=): users who added nothing
// today, and parties whose payment date has passed. Runs at most once per India day unless ?force=1.
app.get('/api/cron/remind', wrap(async (req, res) => {
  const c = await mailCfg();
  const vercelCron = !!process.env.CRON_SECRET && req.headers.authorization === 'Bearer ' + process.env.CRON_SECRET;
  if (!vercelCron && (!req.query.key || String(req.query.key) !== c.cron_key)) return res.status(403).json({ error: 'Not allowed' });
  const today = istToday();
  if (c.remind_last === today && !req.query.force) return res.json({ ok: true, skipped: 'already sent today' });
  await pool.query('UPDATE settings SET remind_last = $1 WHERE id = 1', [today]);
  await cleanPhotos();
  const prefs = await pushPrefs(), out = { ok: true, noEntry: 0, overdue: 0 };
  if (prefs.remind) {
    const { rows } = await pool.query(`SELECT s.* FROM push_subs s JOIN users u ON u.username = s.username
      WHERE u.role = 'user' AND NOT EXISTS (SELECT 1 FROM tx WHERE tx.username = s.username AND tx.tx_date = $1)`, [today]);
    out.noEntry = await sendPush(rows, (lang) => { const t = PT[lang] || PT.en; return { title: '📝 ' + t.noEntry, body: t.noEntry2, go: 'tx' }; });
  }
  if (prefs.overdue) {
    const { rows: od } = await pool.query(`SELECT p.name, p.owner, p.due, SUM(CASE WHEN t.kind = 'out' THEN t.amount ELSE -t.amount END) AS bal
      FROM parties p JOIN tx t ON t.party_id = p.id AND (p.common OR t.username = p.owner)
      WHERE p.due <> '' AND p.due < $1 GROUP BY p.id HAVING SUM(CASE WHEN t.kind = 'out' THEN t.amount ELSE -t.amount END) > 0`, [today]);
    const by = {};
    od.forEach((p) => { (by[p.owner] = by[p.owner] || []).push({ name: p.name, bal: Number(p.bal), late: Math.round((Date.parse(today) - Date.parse(p.due)) / 864e5) }); });
    const owners = Object.keys(by);
    if (owners.length) {
      const { rows: subs } = await pool.query('SELECT * FROM push_subs WHERE username = ANY($1)', [owners]);
      out.overdue = await sendPush(subs, (lang, s) => {
        const t = PT[lang] || PT.en, list = by[s.username].sort((a, b) => b.late - a.late), tot = list.reduce((x, p) => x + p.bal, 0);
        return { title: '⏰ ' + t.overdue + ': ' + list.length + ' ' + (lang === 'en' && list.length === 1 ? 'party' : t.parties) + ' · ' + pr(tot),
          body: list.slice(0, 4).map((p) => p.name + ' ' + pr(p.bal) + ' (' + p.late + ' ' + t.late + ')').join(', ') + (list.length > 4 ? ' …' : ''), go: 'ageing' };
      });
    }
  }
  res.json(out);
}));

app.post('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const u = uname(req.body.username), p = String(req.body.password || '');
  if (!u) return res.status(400).json({ error: 'Enter a username' });
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  // A deleted user's entries stay in the books under their name; a new person must not take them over.
  const used = await pool.query(`SELECT 1 FROM tx WHERE username = $1 UNION ALL SELECT 1 FROM parties WHERE owner = $1
    UNION ALL SELECT 1 FROM transfers WHERE from_user = $1 OR to_user = $1 UNION ALL SELECT 1 FROM tx_history WHERE owner = $1 LIMIT 1`, [u]);
  const taken = (await pool.query('SELECT 1 FROM users WHERE username = $1', [u])).rowCount > 0;
  if (!taken && used.rowCount) return res.status(409).json({ error: 'This username was used before and its entries are still in the books. Choose another name.' });
  const hash = await bcrypt.hash(p, 10);
  const r = await pool.query(
    "INSERT INTO users (username, role, pass_hash, tok_after) VALUES ($1,'user',$2,$3) ON CONFLICT DO NOTHING RETURNING username", [u, hash, Math.floor(Date.now() / 1000)]);
  if (!r.rowCount) return res.status(409).json({ error: 'Username already exists' });
  await logAct(req.user.username, u, 'user_add');
  res.json({ ok: true });
}));

app.put('/api/users/:name/password', auth, adminOnly, wrap(async (req, res) => {
  const p = String(req.body.password || '');
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  // Changing a password signs that person out everywhere. If admins change their own, they get a fresh session.
  const name = uname(req.params.name), now = Math.floor(Date.now() / 1000);
  const r = await pool.query('UPDATE users SET pass_hash = $2, tok_after = $3 WHERE username = $1', [name, await bcrypt.hash(p, 10), now]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  await logAct(req.user.username, name, 'user_password');
  res.json(name === req.user.username ? { ok: true, token: sign(name) } : { ok: true });
}));

// Edit a user (admin): display name, username and, optionally, a new password, all in one go.
// A new username is written into every record that names the user (entries, parties, transfers,
// history, notifications), so their books stay exactly the same. They have to sign in again with it.
const RENAME = [['tx', 'username'], ['parties', 'owner'], ['transfers', 'from_user'], ['transfers', 'to_user'], ['transfers', 'req_by'],
  ['activity', 'actor'], ['activity', 'owner'], ['tx_history', 'owner'], ['tx_history', 'actor'], ['push_subs', 'username']];
async function renameRefs(c, from, to) {
  for (const [t, col] of RENAME) await c.query(`UPDATE ${t} SET ${col} = $2 WHERE ${col} = $1`, [from, to]);
  // Transfer entries carry the other person's name in their notes ("⇄ To shams").
  await c.query("UPDATE tx SET notes = '⇄ To ' || $2 WHERE transfer_id IS NOT NULL AND notes = '⇄ To ' || $1", [from, to]);
  await c.query("UPDATE tx SET notes = '⇄ From ' || $2 WHERE transfer_id IS NOT NULL AND notes = '⇄ From ' || $1", [from, to]);
  await c.query("UPDATE tx_history SET snapshot = jsonb_set(snapshot, '{username}', to_jsonb($2::text)) WHERE snapshot->>'username' = $1", [from, to]);
}
app.put('/api/users/:name', auth, adminOnly, wrap(async (req, res) => {
  const name = uname(req.params.name), b = req.body || {};
  const to = b.username === undefined ? name : uname(b.username), full = String(b.full_name == null ? '' : b.full_name).trim().replace(/\s+/g, ' ').slice(0, 60);
  const p = b.password ? String(b.password) : '';
  if (!to) return res.status(400).json({ error: 'Enter a username' });
  if (to.length > 32) return res.status(400).json({ error: 'Username is too long (max 32 characters)' });
  if (p && p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const now = Math.floor(Date.now() / 1000), hash = p ? await bcrypt.hash(p, 10) : null;
  const r = await atomic(async (c) => {
    const cur = await c.query('SELECT username FROM users WHERE username = $1 FOR UPDATE', [name]);
    if (!cur.rowCount) return { code: 404, error: 'User not found' };
    if (to !== name) {
      if ((await c.query('SELECT 1 FROM users WHERE username = $1', [to])).rowCount) return { code: 409, error: 'Username already exists' };
      const used = await c.query(`SELECT 1 FROM tx WHERE username = $1 UNION ALL SELECT 1 FROM parties WHERE owner = $1
        UNION ALL SELECT 1 FROM transfers WHERE from_user = $1 OR to_user = $1 UNION ALL SELECT 1 FROM tx_history WHERE owner = $1 LIMIT 1`, [to]);
      if (used.rowCount) return { code: 409, error: 'This username was used before and its entries are still in the books. Choose another name.' };
      await c.query('UPDATE users SET username = $2, tok_after = $3 WHERE username = $1', [name, to, now]);
      await renameRefs(c, name, to);
    }
    await c.query('UPDATE users SET full_name = $2' + (hash ? ', pass_hash = $3, tok_after = $4' : '') + ' WHERE username = $1',
      hash ? [to, full, hash, now] : [to, full]);
    return { ok: true };
  });
  if (r.code) return res.status(r.code).json({ error: r.error });
  if (to !== name) {
    // Something the old name saved in the moment before the change (it is signed out now) is moved over too.
    try { await atomic((c) => renameRefs(c, name, to)); } catch (e) { console.error('rename follow-up failed:', e.message); }
    await logAct(req.user.username, to, 'user_rename', { kind: null, amount: null, notes: name });
  }
  if (hash) await logAct(req.user.username, to, 'user_password');
  res.json(name === req.user.username && (to !== name || hash) ? { ok: true, token: sign(to) } : { ok: true });
}));

app.delete('/api/users/:name', auth, adminOnly, wrap(async (req, res) => {
  // Their entries stay. Customer links to their parties stop working, transfers still waiting on them
  // are cancelled, open change requests are cleared, and their phones stop getting notifications.
  const name = uname(req.params.name);
  const r = await atomic(async (c) => {
    const d = await c.query("DELETE FROM users WHERE username = $1 AND role <> 'admin'", [name]);
    if (!d.rowCount) return d;
    await c.query('UPDATE parties SET share_token = NULL WHERE owner = $1 AND NOT common', [name]);
    await c.query("UPDATE transfers SET status = 'cancelled', done_ts = $2 WHERE status = 'pending' AND (from_user = $1 OR to_user = $1)", [name, Date.now()]);
    await c.query('UPDATE transfers SET req_kind = NULL, req_by = NULL, req_amount = NULL, req_notes = NULL, req_ts = NULL WHERE req_kind IS NOT NULL AND (from_user = $1 OR to_user = $1)', [name]);
    await c.query('DELETE FROM push_subs WHERE username = $1', [name]);
    return d;
  });
  if (!r.rowCount) return res.status(404).json({ error: 'User not found (admin cannot be deleted)' });
  await logAct(req.user.username, name, 'user_delete');
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

// Database setup runs once per start of the server. It is skipped when the schema has not changed
// since it last ran, so a fresh copy of the server on Vercel answers quickly.
const SCHEMA_V = crypto.createHash('sha1').update(SCHEMA).digest('hex');
async function initDb() {
  let cur = null;
  try { cur = (await pool.query('SELECT schema_v FROM meta WHERE id = 1')).rows[0].schema_v; } catch (e) { /* new database or older schema */ }
  if (cur === SCHEMA_V) return;
  // Several copies of the server can start at once (Vercel). A transaction-scoped lock lets one of them
  // set up the database while the others wait, then they see it is done (works through the pooler too).
  await atomic(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(727274)');
    let v = null;
    try { await c.query('SAVEPOINT s'); v = (await c.query('SELECT schema_v FROM meta WHERE id = 1')).rows[0].schema_v; }
    catch (e) { await c.query('ROLLBACK TO SAVEPOINT s'); }
    if (v === SCHEMA_V) return;
    await c.query(SCHEMA);
    await c.query('ALTER TABLE meta ADD COLUMN IF NOT EXISTS schema_v TEXT');
    await c.query('UPDATE meta SET schema_v = $1 WHERE id = 1', [SCHEMA_V]);
  });
}
// Photos of entries deleted more than 30 days ago can no longer be restored, so they are dropped (daily).
const cleanPhotos = () => pool.query(`DELETE FROM tx_photos p WHERE NOT EXISTS (SELECT 1 FROM tx WHERE tx.id = p.tx_id)
  AND NOT EXISTS (SELECT 1 FROM tx_history h WHERE h.tx_id = p.tx_id AND h.action = 'delete' AND h.ts > $1)`, [Date.now() - 30 * 86400000])
  .catch((e) => console.error('photo cleanup failed:', e.message));
let ready = null;
const whenReady = () => ready || (ready = initDb().catch((e) => { ready = null; throw e; }));

if (require.main === module) {
  // Run as a normal server (Render, or locally): set up the database, retrying while it starts, then listen.
  (async () => {
    for (let i = 1; ; i++) {
      try { await whenReady(); break; }
      catch (e) {
        console.error('DB init failed (attempt ' + i + '):', e.message);
        if (i >= 10) process.exit(1);
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
    app.listen(PORT, '0.0.0.0', () => console.log('Cashflow listening on ' + PORT));
  })();
} else {
  // Loaded by Vercel (api/index.js): every request waits until the database is set up.
  module.exports = (req, res) => whenReady().then(() => app(req, res), (e) => {
    console.error('DB init failed:', e.message);
    res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'Server is starting, try again' }));
  });
}
