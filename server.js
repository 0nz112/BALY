// خادم نظام ستي ليدر صلاح الدين — Express + PostgreSQL (Railway)
'use strict';
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
// إذا لم يُحدَّد JWT_SECRET يُولَّد مفتاح تلقائياً ويُحفظ في قاعدة البيانات
let SECRET = (process.env.JWT_SECRET || '').trim();
const DB_URL = (process.env.DATABASE_URL || '').trim();
if (!DB_URL) { console.error('DATABASE_URL مفقود — اربط قاعدة PostgreSQL بالخدمة'); process.exit(1); }

const noSsl = /localhost|127\.0\.0\.1|\.railway\.internal/.test(DB_URL) || process.env.PGSSL === 'disable';
const pool = new Pool({ connectionString: DB_URL, ssl: noSsl ? false : { rejectUnauthorized: false }, max: 10 });

// ===== صلاحيات المجموعات =====
const COLS = new Set(['settings', 'boards', 'managers', 'promoters', 'captains', 'bonuses', 'budgets']);
const TEAM_COLS = new Set(['captains', 'bonuses']);            // المدير يرى فريقه فقط
const MANAGER_READ = new Set(['settings', 'boards', 'managers', 'promoters', 'captains', 'bonuses']); // الميزانية للستي ليدر فقط
const ID_RE = /^[A-Za-z0-9_\-.]{1,120}$/;
const FIELD_RE = /^[A-Za-z0-9_]{1,60}$/;
const genId = () => Date.now().toString(36) + crypto.randomBytes(6).toString('hex');

const canRead = (u, col) => COLS.has(col) && (u.role === 'leader' || (u.role === 'manager' && MANAGER_READ.has(col)));
const visible = (u, col, data) => u.role === 'leader' || !TEAM_COLS.has(col) || (data && data.managerId === u.manager_id);
const isLeader = u => u && u.role === 'leader';

async function init() {
  await pool.query(`
    create table if not exists docs (
      col text not null, id text not null, data jsonb not null,
      updated_at timestamptz not null default now(), primary key (col, id));
    create index if not exists docs_mgr on docs (col, (data->>'managerId'));
    create index if not exists docs_reg on docs (col, (data->>'regDate') collate "C");
    create table if not exists users (
      id text primary key, email text unique not null, password_hash text not null,
      role text not null, manager_id text, name text, token_version int not null default 0,
      created_at timestamptz not null default now());
    create table if not exists meta (k text primary key, v text not null);`);
  if (SECRET.length < 16) {
    if (SECRET) console.warn('تنبيه: JWT_SECRET أقصر من 16 حرفاً، سيُستخدم مفتاح تلقائي بدلاً منه');
    const r = await pool.query("select v from meta where k='jwt_secret'");
    if (r.rows.length) SECRET = r.rows[0].v;
    else {
      SECRET = crypto.randomBytes(48).toString('hex');
      await pool.query("insert into meta (k,v) values ('jwt_secret',$1) on conflict (k) do nothing", [SECRET]);
      const again = await pool.query("select v from meta where k='jwt_secret'"); SECRET = again.rows[0].v;
      console.log('أُنشئ مفتاح جلسات تلقائي وحُفظ في قاعدة البيانات');
    }
  }
  // حساب الستي ليدر من متغيرات البيئة (يُنشأ أو تُحدَّث كلمة مروره عند كل تشغيل)
  const email = (process.env.LEADER_EMAIL || '').trim().toLowerCase();
  const pass = process.env.LEADER_PASSWORD || '';
  if (email && pass) {
    const r = await pool.query('select id, password_hash from users where email=$1', [email]);
    if (!r.rows.length) {
      await pool.query('insert into users (id,email,password_hash,role,name) values ($1,$2,$3,$4,$5)',
        [genId(), email, await bcrypt.hash(pass, 10), 'leader', process.env.LEADER_NAME || 'الستي ليدر']);
      console.log('أُنشئ حساب الستي ليدر:', email);
    } else if (!(await bcrypt.compare(pass, r.rows[0].password_hash))) {
      await pool.query("update users set password_hash=$2, role='leader', token_version=token_version+1 where id=$1",
        [r.rows[0].id, await bcrypt.hash(pass, 10)]);
      console.log('حُدّثت كلمة مرور الستي ليدر');
    }
  } else console.warn('تنبيه: LEADER_EMAIL و LEADER_PASSWORD غير محددين');
}

// ===== التطبيق =====
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  res.set('X-Frame-Options', 'DENY');
  // حماية من الطلبات القادمة من مواقع أخرى
  if (req.path.startsWith('/api/') && req.method !== 'GET') {
    const o = req.get('origin');
    if (o && new URL(o).host !== req.get('host')) return res.status(403).json({ error: 'origin' });
  }
  next();
});

function sign(res, req, u) {
  const t = jwt.sign({ uid: u.id, v: u.token_version }, SECRET, { expiresIn: '30d' });
  res.cookie('sid', t, { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 30 * 864e5, path: '/' });
}
const pub = u => ({ uid: u.id, email: u.email, role: u.role, managerId: u.manager_id, name: u.name });

async function auth(req, res, next) {
  const t = req.cookies.sid;
  if (!t) return res.status(401).json({ error: 'unauthenticated' });
  try {
    const p = jwt.verify(t, SECRET);
    const r = await pool.query('select * from users where id=$1', [p.uid]);
    const u = r.rows[0];
    if (!u || u.token_version !== p.v) return res.status(401).json({ error: 'unauthenticated' });
    req.user = u; next();
  } catch (e) { return res.status(401).json({ error: 'unauthenticated' }); }
}
const leaderOnly = (req, res, next) => isLeader(req.user) ? next() : res.status(403).json({ error: 'forbidden' });
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'server' }); });

// ----- الدخول -----
const attempts = new Map();
app.post('/api/login', wrap(async (req, res) => {
  const ip = req.ip, now = Date.now();
  const a = attempts.get(ip) || { n: 0, t: now };
  if (now - a.t > 15 * 60e3) { a.n = 0; a.t = now; }
  if (a.n >= 10) return res.status(429).json({ error: 'too-many' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const r = await pool.query('select * from users where email=$1', [email]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password_hash))) {
    a.n++; attempts.set(ip, a); return res.status(401).json({ error: 'bad-credentials' });
  }
  attempts.delete(ip); sign(res, req, u); res.json(pub(u));
}));
app.post('/api/logout', (req, res) => { res.clearCookie('sid', { path: '/' }); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));
app.post('/api/me/password', auth, wrap(async (req, res) => {
  const { current, next } = req.body || {};
  if (!next || String(next).length < 6) return res.status(400).json({ error: 'weak' });
  if (!(await bcrypt.compare(String(current || ''), req.user.password_hash))) return res.status(403).json({ error: 'bad-current' });
  const r = await pool.query('update users set password_hash=$2, token_version=token_version+1 where id=$1 returning *',
    [req.user.id, await bcrypt.hash(String(next), 10)]);
  sign(res, req, r.rows[0]); res.json({ ok: true });
}));

// ----- حسابات مدراء المبيعات (للستي ليدر) -----
app.post('/api/users', auth, leaderOnly, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const managerId = String(req.body.managerId || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'email' });
  if (pw.length < 6) return res.status(400).json({ error: 'weak' });
  if (!ID_RE.test(managerId)) return res.status(400).json({ error: 'manager' });
  const ex = await pool.query('select 1 from users where email=$1', [email]);
  if (ex.rows.length) return res.status(409).json({ error: 'exists' });
  const id = genId();
  await pool.query('insert into users (id,email,password_hash,role,manager_id,name) values ($1,$2,$3,$4,$5,$6)',
    [id, email, await bcrypt.hash(pw, 10), 'manager', managerId, String(req.body.name || '')]);
  res.json({ uid: id });
}));
app.delete('/api/users/:id', auth, leaderOnly, wrap(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'self' });
  await pool.query("delete from users where id=$1 and role<>'leader'", [req.params.id]);
  res.json({ ok: true });
}));
app.post('/api/users/:id/password', auth, leaderOnly, wrap(async (req, res) => {
  const pw = String(req.body.password || '');
  if (pw.length < 6) return res.status(400).json({ error: 'weak' });
  await pool.query("update users set password_hash=$2, token_version=token_version+1 where id=$1 and role<>'leader'",
    [req.params.id, await bcrypt.hash(pw, 10)]);
  res.json({ ok: true });
}));

// ----- التحديث اللحظي (SSE) -----
const clients = new Set();
app.get('/api/events', auth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders(); res.write('retry: 3000\n\n');
  const c = { res }; clients.add(c);
  const hb = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(hb); clients.delete(c); });
});
const broadcast = cols => { for (const col of new Set(cols)) for (const c of clients) c.res.write(`data: ${JSON.stringify({ col })}\n\n`); };

// ----- مخزن المستندات -----
const OPS = { '==': '=', '>=': '>=', '<=': '<=', '>': '>', '<': '<', '!=': '<>' };
function matches(d, w) {
  for (const [f, op, v] of w) {
    const x = d[f];
    if (op === '==' && x !== v) return false;
    if (op === '!=' && x === v) return false;
    if (op === '>=' && !(x >= v)) return false;
    if (op === '<=' && !(x <= v)) return false;
    if (op === '>' && !(x > v)) return false;
    if (op === '<' && !(x < v)) return false;
    if (op === 'in' && !(Array.isArray(v) && v.includes(x))) return false;
  }
  return true;
}
app.get('/api/col/:col', auth, wrap(async (req, res) => {
  const col = req.params.col, u = req.user;
  if (!canRead(u, col)) return res.status(403).json({ error: 'forbidden' });
  let where = [];
  try { where = req.query.where ? JSON.parse(req.query.where) : []; } catch (e) { return res.status(400).json({ error: 'where' }); }
  if (!Array.isArray(where)) return res.status(400).json({ error: 'where' });
  const args = [col]; let sql = 'select id, data from docs where col=$1';
  if (u.role !== 'leader' && TEAM_COLS.has(col)) { args.push(u.manager_id); sql += ` and data->>'managerId'=$${args.length}`; }
  for (const w of where) {
    const [f, op, v] = w || [];
    if (!FIELD_RE.test(String(f)) || !(op in OPS || op === 'in')) return res.status(400).json({ error: 'where' });
    if (typeof v === 'string' && op in OPS) { args.push(v); sql += ` and (data->>'${f}') collate "C" ${OPS[op]} $${args.length}`; }
    else if (typeof v === 'boolean' && op === '==') { sql += ` and (data->>'${f}')='${v}'`; }
  }
  sql += ' order by id';
  let rows = (await pool.query(sql, args)).rows.filter(r => matches(r.data, where) && visible(u, col, r.data));
  const lim = parseInt(req.query.limit, 10); if (lim > 0) rows = rows.slice(0, lim);
  res.json({ docs: rows.map(r => ({ id: r.id, data: r.data })) });
}));
app.get('/api/doc/:col/:id', auth, wrap(async (req, res) => {
  const { col, id } = req.params, u = req.user;
  if (!canRead(u, col)) return res.status(403).json({ error: 'forbidden' });
  const r = await pool.query('select data from docs where col=$1 and id=$2', [col, id]);
  const d = r.rows[0] && r.rows[0].data;
  res.json({ data: d && visible(u, col, d) ? d : null });
}));

function checkWrite(col, id, data, needData) {
  if (!COLS.has(col) || !ID_RE.test(String(id))) return 'path';
  if (needData && (!data || typeof data !== 'object' || Array.isArray(data))) return 'data';
  return null;
}
async function applyOp(q, op) {
  const { col, id, data } = op;
  if (op.op === 'set') await q.query(`insert into docs (col,id,data) values ($1,$2,$3)
     on conflict (col,id) do update set data=excluded.data, updated_at=now()`, [col, id, data]);
  else if (op.op === 'update') {
    const r = await q.query('update docs set data = data || $3::jsonb, updated_at=now() where col=$1 and id=$2', [col, id, data]);
    if (!r.rowCount) { const e = new Error('missing'); e.status = 404; throw e; }
  } else if (op.op === 'delete') await q.query('delete from docs where col=$1 and id=$2', [col, id]);
}
const writeRoute = kind => wrap(async (req, res) => {
  const { col, id } = req.params, data = req.body && req.body.data;
  const bad = checkWrite(col, id, data, kind !== 'delete');
  if (bad) return res.status(400).json({ error: bad });
  try { await applyOp(pool, { op: kind, col, id, data }); }
  catch (e) { if (e.status === 404) return res.status(404).json({ error: 'not-found' }); throw e; }
  broadcast([col]); res.json({ ok: true });
});
app.put('/api/doc/:col/:id', auth, leaderOnly, writeRoute('set'));
app.patch('/api/doc/:col/:id', auth, leaderOnly, writeRoute('update'));
app.delete('/api/doc/:col/:id', auth, leaderOnly, writeRoute('delete'));
app.post('/api/batch', auth, leaderOnly, wrap(async (req, res) => {
  const ops = (req.body && req.body.ops) || [];
  if (!Array.isArray(ops) || ops.length > 500) return res.status(400).json({ error: 'ops' });
  for (const o of ops) { if (!['set', 'update', 'delete'].includes(o.op) || checkWrite(o.col, o.id, o.data, o.op !== 'delete')) return res.status(400).json({ error: 'op' }); }
  const c = await pool.connect();
  try { await c.query('begin'); for (const o of ops) await applyOp(c, o); await c.query('commit'); }
  catch (e) { await c.query('rollback'); if (e.status === 404) return res.status(404).json({ error: 'not-found' }); throw e; }
  finally { c.release(); }
  broadcast(ops.map(o => o.col)); res.json({ ok: true });
}));

app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], setHeaders: r => r.set('Cache-Control', 'no-cache') }));
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

init().then(() => app.listen(PORT, () => console.log('النظام يعمل على المنفذ', PORT)))
  .catch(e => { console.error('فشل الاتصال بقاعدة البيانات', e); process.exit(1); });
