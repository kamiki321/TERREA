// Terrea Hailing Log - Vercel single-function bundle
// COMPLETE API BACKEND IS BUNDLED INTO THIS FILE.
// Vercel should detect exactly ONE Serverless Function: /api/index.js.

const __modules = Object.create(null);
const __cache = Object.create(null);

function __normalize(parentId, request) {
  const base = parentId.includes('/') ? parentId.slice(0, parentId.lastIndexOf('/') + 1) : '';
  const raw = (base + request).split('/');
  const stack = [];
  for (const part of raw) {
    if (!part || part === '.') continue;
    if (part === '..') stack.pop(); else stack.push(part);
  }
  return stack.join('/');
}

function __load(id) {
  if (__cache[id]) return __cache[id].exports;
  const factory = __modules[id];
  if (!factory) throw new Error('Bundled module not found: ' + id);
  const module = { exports: {} };
  __cache[id] = module;
  const localRequire = (request) => {
    if (request.startsWith('.')) return __load(__normalize(id, request));
    return require(request);
  };
  factory(module, module.exports, localRequire);
  return module.exports;
}

__modules["_db"] = function(module, exports, require) {
const { neon } = require('@neondatabase/serverless');
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL || process.env.NEON_DATABASE_URL;
if (!DATABASE_URL) throw new Error('Database URL belum dikonfigurasi. Tambahkan DATABASE_URL di Vercel Environment Variables.');
const sql = neon(DATABASE_URL);
async function initDatabase() {
  await sql`CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS hailing_records (
    id TEXT PRIMARY KEY,
    no INTEGER NOT NULL,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    date TEXT,
    time TEXT,
    posisi TEXT,
    destination TEXT,
    cargo TEXT,
    crew_count INTEGER,
    captain TEXT,
    captain_phone TEXT,
    owner TEXT,
    owner_phone TEXT,
    company TEXT,
    nominal BIGINT,
    raw_input TEXT,
    parser_confidence INTEGER,
    ops_id TEXT,
    ops_name TEXT,
    CONSTRAINT fk_hailing_operation FOREIGN KEY (ops_id) REFERENCES operations(id) ON UPDATE CASCADE ON DELETE SET NULL
  )`;
  await sql`CREATE TABLE IF NOT EXISTS vessels (
    id TEXT PRIMARY KEY,
    hailing_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT,
    gt TEXT,
    CONSTRAINT fk_vessel_hailing FOREIGN KEY (hailing_id) REFERENCES hailing_records(id) ON DELETE CASCADE
  )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_hailing_date ON hailing_records(date)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_hailing_ops ON hailing_records(ops_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_hailing_owner ON hailing_records(owner)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_vessels_hailing ON vessels(hailing_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_vessels_name ON vessels(name)`;
}
module.exports = { sql, initDatabase };

};

__modules["_auth"] = function(module, exports, require) {
const crypto = require('crypto');
const { sql } = require('./_db');

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const COOKIE_NAME = 'terrea_refresh_token';

const PASSWORD_RULE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

function authError(message, status = 401) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function validatePassword(password) {
  return typeof password === 'string' && PASSWORD_RULE.test(password);
}

function passwordRuleMessage() {
  return 'Password minimal 8 karakter, mengandung 1 huruf uppercase, 1 angka, dan 1 karakter special.';
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function getJwtSecret() {
  // Vercel deployment must keep a stable secret across serverless instances.
  // Prefer AUTH_JWT_SECRET when configured. For this one-function package,
  // fall back to a deterministic secret derived from the private database URL
  // so login does not fail with HTTP 500 when the optional JWT variable was
  // accidentally omitted. The database URL should itself remain secret.
  const configured = String(process.env.AUTH_JWT_SECRET || '').trim();
  if (configured.length >= 32) return configured;

  const databaseSecret = String(
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.POSTGRES_PRISMA_URL ||
    process.env.NEON_DATABASE_URL ||
    ''
  );
  if (!databaseSecret) {
    throw new Error('DATABASE_URL belum dikonfigurasi di Vercel Environment Variables.');
  }

  return crypto.createHash('sha256')
    .update('TERREA-HAILING-JWT-V1\0' + databaseSecret)
    .digest('hex');
}

function createAccessToken(user) {
  const secret = getJwtSecret();
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({
    sub: String(user.id),
    username: user.username,
    iat: now,
    exp: now + ACCESS_TTL_SECONDS
  }));
  const data = `${header}.${payload}`;
  const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${signature}`;
}

function verifyAccessToken(token) {
  try {
    const secret = getJwtSecret();
    if (!secret || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const expected = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (!data.exp || data.exp <= now || !data.sub) return null;
    return data;
  } catch (_) { return null; }
}

function hashPassword(password, salt = crypto.randomBytes(16)) {
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

function verifyPassword(password, encoded) {
  try {
    const [scheme, saltText, hashText] = String(encoded || '').split('$');
    if (scheme !== 'scrypt' || !saltText || !hashText) return false;
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(hashText, 'base64url');
    const actual = crypto.scryptSync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch (_) { return false; }
}

function randomRefreshToken() { return crypto.randomBytes(48).toString('base64url'); }
function hashRefreshToken(token) { return crypto.createHash('sha256').update(String(token)).digest('hex'); }

function parseCookies(req) {
  const raw = req.headers?.cookie || '';
  const out = {};
  raw.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function setRefreshCookie(res, token) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${REFRESH_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

async function ensureAuthDatabase() {
  await sql`CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at)`;

  const count = await sql`SELECT COUNT(*)::int AS count FROM "user"`;
  if (Number(count[0].count) === 0) {
    const username = process.env.DEFAULT_ADMIN_USERNAME || 'kujang642';
    const password = process.env.DEFAULT_ADMIN_PASSWORD;
    // The fallback is a precomputed scrypt hash of the requested default password.
    // The plaintext password is never stored in the database. Set DEFAULT_ADMIN_PASSWORD
    // in Vercel to replace it with a new initial password.
    const fallbackHash = 'scrypt$CFi4DalPS3ykbRT1RUYCQw$fxyAucJpDlOQQEyW1AMS2ZmqKQFuOtlZCUMpz8IZMImyqQimexgJtoqkgQDUcu1ZwlbdRK5qbb9UdqIIlTWm1A';
    const passwordHash = password ? (validatePassword(password) ? hashPassword(password) : (()=>{ throw new Error('DEFAULT_ADMIN_PASSWORD tidak memenuhi aturan password.'); })()) : fallbackHash;
    await sql`INSERT INTO "user"(username,password) VALUES(${username},${passwordHash})`;
  }
}

async function issueSession(user) {
  const refreshToken = randomRefreshToken();
  const tokenHash = hashRefreshToken(refreshToken);
  const sessionId = crypto.randomBytes(18).toString('base64url');
  await sql`INSERT INTO user_sessions(id,user_id,token_hash,expires_at)
    VALUES(${sessionId},${user.id},${tokenHash},NOW() + (${REFRESH_TTL_SECONDS} * INTERVAL '1 second'))`;
  return { accessToken: createAccessToken(user), refreshToken, sessionId };
}

async function rotateRefreshSession(refreshToken) {
  const tokenHash = hashRefreshToken(refreshToken);
  const rows = await sql`SELECT s.id,s.user_id,u.username,s.expires_at,s.revoked_at
    FROM user_sessions s JOIN "user" u ON u.id=s.user_id
    WHERE s.token_hash=${tokenHash} LIMIT 1`;
  if (!rows.length) throw authError('Refresh token tidak valid.', 401);
  const session = rows[0];
  if (session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) throw authError('Session sudah berakhir. Silakan login kembali.', 401);

  const next = await issueSession({ id: session.user_id, username: session.username });
  await sql`UPDATE user_sessions SET revoked_at=NOW(), last_used_at=NOW() WHERE id=${session.id}`;
  return { ...next, userId: session.user_id, username: session.username };
}

async function requireAuth(req) {
  const auth = String(req.headers?.authorization || '');
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const payload = verifyAccessToken(token);
  if (!payload) throw authError('Sesi login tidak valid atau sudah berakhir.', 401);
  const rows = await sql`SELECT id,username FROM "user" WHERE id=${Number(payload.sub)} LIMIT 1`;
  if (!rows.length) throw authError('Pengguna tidak ditemukan.', 401);
  return rows[0];
}

async function cleanupExpiredSessions() {
  await sql`DELETE FROM user_sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '30 days'`;
}

module.exports = {
  COOKIE_NAME, ACCESS_TTL_SECONDS, REFRESH_TTL_SECONDS,
  validatePassword, passwordRuleMessage, hashPassword, verifyPassword,
  parseCookies, setRefreshCookie, clearRefreshCookie,
  ensureAuthDatabase, issueSession, rotateRefreshSession,
  requireAuth, cleanupExpiredSessions
};

};

__modules["_lib"] = function(module, exports, require) {
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { sql, initDatabase } = require('./_db');
const { ensureAuthDatabase } = require('./_auth');

const MASTER_FILE = path.join(process.cwd(), 'data', 'master.json');
let initialized = false;
let initPromise = null;

const now = () => new Date().toISOString();
const makeId = () => crypto.randomBytes(9).toString('base64url') + Date.now().toString(36);

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  return res.end(JSON.stringify(payload));
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function parseJsonText(text) {
  const s = String(text ?? '').trim();
  if (!s) return null;
  try { return JSON.parse(s); }
  catch (e) {
    const err = new Error('JSON request tidak valid: ' + e.message);
    err.code = 'INVALID_JSON';
    throw err;
  }
}

/**
 * Vercel may expose JSON as req.body, while some runtimes expose rawBody or
 * leave the Node request stream available. Prefer the parsed body and only
 * fall back to rawBody/stream when necessary.
 */
async function body(req) {
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) return parseJsonText(req.body.toString('utf8')) || {};
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') return parseJsonText(req.body) || {};
  }

  if (req.rawBody !== undefined && req.rawBody !== null) {
    if (Buffer.isBuffer(req.rawBody)) return parseJsonText(req.rawBody.toString('utf8')) || {};
    if (typeof req.rawBody === 'string') return parseJsonText(req.rawBody) || {};
  }

  // If the runtime has already consumed the request stream, do not throw a
  // misleading "Unexpected end of JSON input". Return an empty object so the
  // endpoint can report the actual missing payload.
  if (req.readable === false || req.complete === true) return {};

  return new Promise((resolve, reject) => {
    let s = '';
    let settled = false;
    const finish = (fn, value) => { if (!settled) { settled = true; fn(value); } };
    req.on('data', chunk => {
      s += chunk.toString();
      if (s.length > 10 * 1024 * 1024) {
        const err = new Error('Payload terlalu besar (maksimal 10 MB)');
        err.code = 'PAYLOAD_TOO_LARGE';
        finish(reject, err);
      }
    });
    req.on('end', () => {
      try { finish(resolve, parseJsonText(s) || {}); }
      catch (e) { finish(reject, e); }
    });
    req.on('error', e => finish(reject, e));
  });
}

async function seedMasterIfEmpty() {
  const c = await sql`SELECT COUNT(*)::int AS count FROM hailing_records`;
  if (Number(c[0].count) !== 0 || !fs.existsSync(MASTER_FILE)) return;

  const raw = fs.readFileSync(MASTER_FILE, 'utf8').trim();
  if (!raw) {
    console.warn('master.json kosong; database dibiarkan kosong. Import manual tetap tersedia.');
    return;
  }

  let master;
  try {
    master = JSON.parse(raw);
  } catch (e) {
    // A bad/empty bundled seed file must never break /api/health or CRUD.
    console.warn('master.json tidak valid; seed dilewati:', e.message);
    return;
  }
  if (!Array.isArray(master) || !master.length) return;

  for (const item of master) await saveRecord(item, item.id);
}

async function ensureInitialized() {
  if (initialized) return;
  if (!initPromise) {
    initPromise = (async () => {
      await initDatabase();
      await ensureAuthDatabase();
      await seedMasterIfEmpty();
      initialized = true;
    })().catch(e => {
      initPromise = null;
      throw e;
    });
  }
  await initPromise;
}

async function nextNo() {
  const r = await sql`SELECT COALESCE(MAX(no),0)+1 AS n FROM hailing_records`;
  return Number(r[0].n);
}

async function ensureOperation(id, name) {
  if (!id || !name) return;
  const t = now();
  await sql`INSERT INTO operations(id,name,created_at,updated_at)
    VALUES(${id},${String(name)},${t},${t})
    ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,updated_at=NOW()`;
}

function normalize(input = {}, existing = {}) {
  const r = { ...existing, ...input };
  return {
    id: r.id || makeId(),
    no: Number(r.no) > 0 ? Number(r.no) : null,
    createdAt: r.createdAt || now(),
    updatedAt: now(),
    date: r.date || null,
    time: r.time || null,
    posisi: r.posisi ?? '-',
    destination: r.destination ?? '',
    cargo: r.cargo ?? '',
    crewCount: r.crewCount === '' || r.crewCount == null ? null : Number(r.crewCount),
    captain: r.captain || null,
    captainPhone: r.captainPhone || null,
    owner: r.owner || null,
    ownerPhone: r.ownerPhone || null,
    company: r.company || null,
    nominal: r.nominal === '' || r.nominal == null ? null : Number(r.nominal),
    rawInput: r.rawInput ?? null,
    parserConfidence: r.parserConfidence == null ? null : Number(r.parserConfidence),
    opsId: r.opsId || null,
    opsName: r.opsName || null,
    vessels: Array.isArray(r.vessels) ? r.vessels : []
  };
}

function mapVessels(rows) {
  return rows.map(v => ({
    id: v.id,
    name: v.name,
    ...(v.type ? { type: v.type } : {}),
    ...(v.gt != null ? { gt: v.gt } : {})
  }));
}

function mapRecord(row, vessels) {
  return {
    id: row.id,
    no: row.no,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    vessels,
    posisi: row.posisi,
    destination: row.destination,
    cargo: row.cargo,
    ...(row.crew_count != null ? { crewCount: row.crew_count } : {}),
    ...(row.captain ? { captain: row.captain } : {}),
    ...(row.captain_phone ? { captainPhone: row.captain_phone } : {}),
    ...(row.owner ? { owner: row.owner } : {}),
    ...(row.owner_phone ? { ownerPhone: row.owner_phone } : {}),
    ...(row.company ? { company: row.company } : {}),
    ...(row.nominal != null ? { nominal: Number(row.nominal) } : {}),
    ...(row.raw_input != null ? { rawInput: row.raw_input } : {}),
    ...(row.parser_confidence != null ? { parserConfidence: row.parser_confidence } : {}),
    ...(row.date ? { date: row.date } : {}),
    ...(row.time ? { time: row.time } : {}),
    ...(row.ops_id ? { opsId: row.ops_id } : {}),
    ...(row.ops_name ? { opsName: row.ops_name } : {})
  };
}

async function getRecord(id) {
  const r = await sql`SELECT * FROM hailing_records WHERE id=${id}`;
  if (!r.length) return null;
  const v = await sql`SELECT id,name,type,gt FROM vessels WHERE hailing_id=${id} ORDER BY id`;
  return mapRecord(r[0], mapVessels(v));
}

async function allRecords() {
  const rows = await sql`SELECT * FROM hailing_records ORDER BY no ASC`;
  const v = await sql`SELECT id,hailing_id,name,type,gt FROM vessels ORDER BY hailing_id,id`;
  const m = new Map();
  for (const x of v) {
    if (!m.has(x.hailing_id)) m.set(x.hailing_id, []);
    m.get(x.hailing_id).push({
      id: x.id,
      name: x.name,
      ...(x.type ? { type: x.type } : {}),
      ...(x.gt != null ? { gt: x.gt } : {})
    });
  }
  return rows.map(r => mapRecord(r, m.get(r.id) || []));
}

async function saveRecord(input, id = null) {
  let existing = null;
  let existingVessels = [];
  if (id) {
    const rows = await sql`SELECT * FROM hailing_records WHERE id=${id}`;
    existing = rows[0] || null;
    if (existing) {
      const vr = await sql`SELECT id,name,type,gt FROM vessels WHERE hailing_id=${id} ORDER BY id`;
      existingVessels = mapVessels(vr);
    }
  }

  const ex = existing ? {
    id: existing.id,
    no: existing.no,
    createdAt: existing.created_at,
    updatedAt: existing.updated_at,
    date: existing.date,
    time: existing.time,
    posisi: existing.posisi,
    destination: existing.destination,
    cargo: existing.cargo,
    crewCount: existing.crew_count,
    captain: existing.captain,
    captainPhone: existing.captain_phone,
    owner: existing.owner,
    ownerPhone: existing.owner_phone,
    company: existing.company,
    nominal: existing.nominal,
    rawInput: existing.raw_input,
    parserConfidence: existing.parser_confidence,
    opsId: existing.ops_id,
    opsName: existing.ops_name,
    vessels: existingVessels
  } : {};

  const r = normalize({ ...input, id: id || input?.id }, ex);
  if (!r.no) r.no = await nextNo();
  if (r.opsId && r.opsName) await ensureOperation(r.opsId, r.opsName);

  await sql`INSERT INTO hailing_records(
    id,no,created_at,updated_at,date,time,posisi,destination,cargo,crew_count,captain,captain_phone,owner,owner_phone,company,nominal,raw_input,parser_confidence,ops_id,ops_name
  ) VALUES(
    ${r.id},${r.no},${r.createdAt},${r.updatedAt},${r.date},${r.time},${r.posisi},${r.destination},${r.cargo},${r.crewCount},${r.captain},${r.captainPhone},${r.owner},${r.ownerPhone},${r.company},${r.nominal},${r.rawInput},${r.parserConfidence},${r.opsId},${r.opsName}
  )
  ON CONFLICT(id) DO UPDATE SET
    no=EXCLUDED.no,updated_at=EXCLUDED.updated_at,date=EXCLUDED.date,time=EXCLUDED.time,posisi=EXCLUDED.posisi,destination=EXCLUDED.destination,cargo=EXCLUDED.cargo,crew_count=EXCLUDED.crew_count,captain=EXCLUDED.captain,captain_phone=EXCLUDED.captain_phone,owner=EXCLUDED.owner,owner_phone=EXCLUDED.owner_phone,company=EXCLUDED.company,nominal=EXCLUDED.nominal,raw_input=EXCLUDED.raw_input,parser_confidence=EXCLUDED.parser_confidence,ops_id=EXCLUDED.ops_id,ops_name=EXCLUDED.ops_name`;

  // For partial updates (e.g. nominal only), vessels are preserved. For a full
  // hailing edit/import with an explicit vessels array, replace the children.
  if (Array.isArray(input.vessels) || !existing) {
    await sql`DELETE FROM vessels WHERE hailing_id=${r.id}`;
    for (const v of r.vessels) {
      if (!v || !String(v.name || '').trim()) continue;
      await sql`INSERT INTO vessels(id,hailing_id,name,type,gt)
        VALUES(${v.id || makeId()},${r.id},${String(v.name).trim()},${v.type || null},${v.gt == null ? null : String(v.gt)})`;
    }
  }
  return getRecord(r.id);
}

module.exports = {
  sql, now, makeId, sendJson, cors, body, ensureInitialized,
  saveRecord, getRecord, allRecords
};

};

__modules["auth-login"] = function(module, exports, require) {
const { sendJson, body } = require('./_lib');
const { sql } = require('./_db');
const { validatePassword, passwordRuleMessage, verifyPassword, issueSession, setRefreshCookie, ensureAuthDatabase } = require('./_auth');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed' });

  try {
    // IMPORTANT: login must initialize ONLY the authentication schema.
    // It must not initialize/seed the whole hailing database because a problem
    // in master.json or another application table should never make login 500.
    await ensureAuthDatabase();

    const b = await body(req);
    const username = String(b.username || '').trim();
    const password = typeof b.password === 'string' ? b.password : '';
    if (!username || !password) return sendJson(res, 400, { error: 'Username dan password wajib diisi.' });
    if (!validatePassword(password)) return sendJson(res, 400, { error: passwordRuleMessage(), code: 'PASSWORD_FORMAT_INVALID' });

    const rows = await sql`SELECT id,username,password FROM "user" WHERE username=${username} LIMIT 1`;
    if (!rows.length) {
      return sendJson(res, 401, { error: 'Username atau password salah.', code: 'INVALID_CREDENTIALS' });
    }
    if (!verifyPassword(password, rows[0].password)) {
      return sendJson(res, 401, { error: 'Username atau password salah.', code: 'INVALID_CREDENTIALS' });
    }

    const user = { id: rows[0].id, username: rows[0].username };
    const session = await issueSession(user);
    setRefreshCookie(res, session.refreshToken);
    return sendJson(res, 200, { ok: true, accessToken: session.accessToken, user });
  } catch (e) {
    console.error('auth login error:', e);
    return sendJson(res, e.status || 500, {
      error: e.message || 'Login gagal.',
      code: e.code || 'AUTH_LOGIN_ERROR'
    });
  }
};

};

__modules["auth-refresh"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { parseCookies, rotateRefreshSession, setRefreshCookie, clearRefreshCookie, ensureAuthDatabase } = require('./_auth');
module.exports = async (req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.status(204).end();
  try{
    await ensureAuthDatabase();
    if(req.method!=='POST') return sendJson(res,405,{error:'Method not allowed'});
    const token=parseCookies(req).terrea_refresh_token;
    if(!token){ clearRefreshCookie(res); return sendJson(res,401,{error:'Refresh token tidak ditemukan.'}); }
    const session=await rotateRefreshSession(token);
    setRefreshCookie(res,session.refreshToken);
    const user={id:session.userId,username:session.username};
    return sendJson(res,200,{ok:true,accessToken:session.accessToken,user});
  }catch(e){
    clearRefreshCookie(res);
    return sendJson(res,e.status||401,{error:e.message||'Session tidak valid.'});
  }
};

};

__modules["auth-logout"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { parseCookies, hashRefreshToken, clearRefreshCookie, ensureAuthDatabase } = require('./_auth');
const { sql } = require('./_db');
module.exports=async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.status(204).end();
  try{
    await ensureAuthDatabase();
    if(req.method!=='POST') return sendJson(res,405,{error:'Method not allowed'});
    const token=parseCookies(req).terrea_refresh_token;
    if(token){
      await sql`UPDATE user_sessions SET revoked_at=NOW() WHERE token_hash=${hashRefreshToken(token)} AND revoked_at IS NULL`;
    }
    clearRefreshCookie(res);
    return sendJson(res,200,{ok:true});
  }catch(e){
    clearRefreshCookie(res);
    return sendJson(res,200,{ok:true});
  }
};

};

__modules["auth-me"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { requireAuth, ensureAuthDatabase } = require('./_auth');
module.exports=async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.status(204).end();
  try{
    await ensureAuthDatabase();
    if(req.method!=='GET') return sendJson(res,405,{error:'Method not allowed'});
    const user=await requireAuth(req);
    return sendJson(res,200,{ok:true,user});
  }catch(e){ return sendJson(res,e.status||401,{error:e.message||'Unauthorized'}); }
};

};

__modules["health"] = function(module, exports, require) {
const { sql, sendJson, ensureInitialized } = require('./_lib');
module.exports = async (req,res)=>{ res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization'); if(req.method==='OPTIONS')return res.status(204).end(); try{await ensureInitialized(); const c=await sql`SELECT COUNT(*)::int AS count FROM hailing_records`; const t=await sql`SELECT NOW() AS now`; return sendJson(res,200,{ok:true,database:'neon-postgresql',records:c[0].count,dbTime:t[0].now});}catch(e){console.error(e);return sendJson(res,500,{ok:false,error:e.message});} };

};

__modules["import"] = function(module, exports, require) {
const { sendJson, body, ensureInitialized, allRecords, sql } = require('./_lib');
const { requireAuth } = require('./_auth');

function cleanString(v) {
  return v == null ? null : String(v);
}
function cleanNumber(v) {
  if (v === '' || v == null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function cleanTimestamp(v, fallback = null) {
  if (v == null || v === '') return fallback;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

function makeImportPayload(data) {
  const records = data.map((item, i) => ({
    id: String(item?.id || `import-${Date.now()}-${i}`),
    no: cleanNumber(item?.no),
    createdAt: cleanTimestamp(item?.createdAt, new Date().toISOString()),
    updatedAt: new Date().toISOString(),
    date: cleanString(item?.date),
    time: cleanString(item?.time),
    posisi: item?.posisi == null ? '-' : String(item.posisi),
    destination: cleanString(item?.destination) || '',
    cargo: cleanString(item?.cargo) || '',
    crewCount: cleanNumber(item?.crewCount),
    captain: cleanString(item?.captain),
    captainPhone: cleanString(item?.captainPhone),
    owner: cleanString(item?.owner),
    ownerPhone: cleanString(item?.ownerPhone),
    company: cleanString(item?.company),
    nominal: cleanNumber(item?.nominal),
    rawInput: cleanString(item?.rawInput),
    parserConfidence: cleanNumber(item?.parserConfidence),
    opsId: item?.opsId && item?.opsName ? String(item.opsId) : null,
    opsName: item?.opsId && item?.opsName ? String(item.opsName) : null
  }));

  const operations = [];
  const opSeen = new Set();
  for (const r of records) {
    if (r.opsId && r.opsName && !opSeen.has(r.opsId)) {
      opSeen.add(r.opsId);
      operations.push({ id: r.opsId, name: r.opsName });
    }
  }

  const vessels = [];
  const vesselIds = new Set();
  for (const item of data) {
    const hailingId = String(item?.id || '');
    if (!hailingId || !Array.isArray(item?.vessels)) continue;
    for (let vi = 0; vi < item.vessels.length; vi++) {
      const v = item.vessels[vi] || {};
      const name = String(v.name || '').trim();
      if (!name) continue;
      let vesselId = String(v.id || `${hailingId}-${vi + 1}`);
      if (vesselIds.has(vesselId)) vesselId = `${hailingId}-${vi + 1}-${vesselIds.size}`;
      vesselIds.add(vesselId);
      vessels.push({
        id: vesselId,
        hailingId,
        name,
        type: cleanString(v.type),
        gt: v.gt == null ? null : String(v.gt)
      });
    }
  }
  return { records, operations, vessels };
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    await ensureInitialized();
    await requireAuth(req);
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed' });

    const payloadBody = await body(req);
    if (!payloadBody || typeof payloadBody !== 'object') {
      return sendJson(res, 400, { error: 'Payload import tidak ditemukan atau bukan JSON object' });
    }

    const mode = payloadBody.mode || 'merge';
    const data = payloadBody.data;
    if (!Array.isArray(data)) return sendJson(res, 400, { error: 'Data import harus berupa array' });
    if (!data.length) return sendJson(res, 400, { error: 'Tidak ada data untuk diimpor' });
    if (!['merge', 'replace'].includes(mode)) return sendJson(res, 400, { error: 'Mode import tidak valid' });

    const payload = makeImportPayload(data);

    // All statements below are ordered to remain compatible with an older
    // Neon schema even if its FK was created without ON DELETE CASCADE.
    if (mode === 'replace') {
      await sql`DELETE FROM vessels`;
      await sql`DELETE FROM hailing_records`;
      await sql`DELETE FROM operations`;
    } else {
      const recordIdsJson = JSON.stringify(payload.records.map(r => ({ id: r.id })));
      await sql`DELETE FROM vessels
        WHERE hailing_id IN (
          SELECT id FROM jsonb_to_recordset(${recordIdsJson}::jsonb) AS x(id text)
        )`;
    }

    if (payload.operations.length) {
      const operationsJson = JSON.stringify(payload.operations);
      await sql`INSERT INTO operations(id,name,created_at,updated_at)
        SELECT id,name,NOW(),NOW()
        FROM jsonb_to_recordset(${operationsJson}::jsonb) AS x(id text,name text)
        ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,updated_at=NOW()`;
    }

    const recordsJson = JSON.stringify(payload.records);
    await sql`INSERT INTO hailing_records(
      id,no,created_at,updated_at,date,time,posisi,destination,cargo,crew_count,captain,captain_phone,owner,owner_phone,company,nominal,raw_input,parser_confidence,ops_id,ops_name
    )
    SELECT
      id,
      COALESCE(no, ROW_NUMBER() OVER (ORDER BY id)::int),
      "createdAt","updatedAt",date,time,posisi,destination,cargo,"crewCount",captain,"captainPhone",owner,"ownerPhone",company,nominal,"rawInput","parserConfidence","opsId","opsName"
    FROM jsonb_to_recordset(${recordsJson}::jsonb) AS x(
      id text,no int,"createdAt" timestamptz,"updatedAt" timestamptz,date text,time text,posisi text,destination text,cargo text,"crewCount" int,captain text,"captainPhone" text,owner text,"ownerPhone" text,company text,nominal bigint,"rawInput" text,"parserConfidence" int,"opsId" text,"opsName" text
    )
    ON CONFLICT(id) DO UPDATE SET
      no=EXCLUDED.no,updated_at=EXCLUDED.updated_at,date=EXCLUDED.date,time=EXCLUDED.time,posisi=EXCLUDED.posisi,destination=EXCLUDED.destination,cargo=EXCLUDED.cargo,crew_count=EXCLUDED.crew_count,captain=EXCLUDED.captain,captain_phone=EXCLUDED.captain_phone,owner=EXCLUDED.owner,owner_phone=EXCLUDED.owner_phone,company=EXCLUDED.company,nominal=EXCLUDED.nominal,raw_input=EXCLUDED.raw_input,parser_confidence=EXCLUDED.parser_confidence,ops_id=EXCLUDED.ops_id,ops_name=EXCLUDED.ops_name`;

    if (payload.vessels.length) {
      const vesselsJson = JSON.stringify(payload.vessels);
      await sql`INSERT INTO vessels(id,hailing_id,name,type,gt)
        SELECT id,"hailingId",name,type,gt
        FROM jsonb_to_recordset(${vesselsJson}::jsonb) AS x(id text,"hailingId" text,name text,type text,gt text)
        ON CONFLICT(id) DO UPDATE SET
          hailing_id=EXCLUDED.hailing_id,name=EXCLUDED.name,type=EXCLUDED.type,gt=EXCLUDED.gt`;
    }

    return sendJson(res, 200, {
      ok: true,
      count: data.length,
      mode,
      records: await allRecords()
    });
  } catch (e) {
    console.error('import error', e);
    const status = e?.code === 'INVALID_JSON' ? 400 : 500;
    return sendJson(res, status, { error: e.message || 'Server error' });
  }
};

};

__modules["record"] = function(module, exports, require) {
const { sendJson, body, ensureInitialized, getRecord, saveRecord, sql } = require('./_lib');
const { requireAuth } = require('./_auth');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  try {
    await ensureInitialized();
    await requireAuth(req);
    const id = String(req.query?.id || '').trim();
    if (!id) return sendJson(res, 400, { error: 'ID data hailing wajib diisi' });

    if (req.method === 'GET') {
      const record = await getRecord(id);
      return record ? sendJson(res, 200, record) : sendJson(res, 404, { error: 'Record tidak ditemukan' });
    }

    if (req.method === 'PUT') {
      if (!(await getRecord(id))) return sendJson(res, 404, { error: 'Record tidak ditemukan' });
      return sendJson(res, 200, await saveRecord(await body(req), id));
    }

    if (req.method === 'DELETE') {
      const existing = await getRecord(id);
      if (!existing) return sendJson(res, 404, { error: 'Record tidak ditemukan' });
      // Explicit child delete keeps this working even when an older Neon schema
      // was created without ON DELETE CASCADE.
      await sql`DELETE FROM vessels WHERE hailing_id=${id}`;
      // Use RETURNING instead of result.count. Neon/Postgres drivers can expose
      // DELETE results without a reliable `count` property even when the row
      // was actually deleted. RETURNING gives us the authoritative result.
      const result = await sql`DELETE FROM hailing_records WHERE id=${id} RETURNING id`;
      if (!result.length) return sendJson(res, 404, { error: 'Record tidak ditemukan' });
      return sendJson(res, 200, { ok: true, id: result[0].id, deleted: 1 });
    }

    return sendJson(res, 405, { error: 'Method not allowed' });
  } catch (e) {
    console.error('record route error', e);
    return sendJson(res, e.status || 500, { error: e.message || 'Server error' });
  }
};

};

__modules["operation"] = function(module, exports, require) {
const { sendJson, ensureInitialized, sql } = require('./_lib');
const { requireAuth } = require('./_auth');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  try {
    await ensureInitialized();
    await requireAuth(req);
    const id = String(req.query?.id || '').trim();
    if (!id) return sendJson(res, 400, { error: 'ID operasi wajib diisi' });
    if (req.method !== 'DELETE') return sendJson(res, 405, { error: 'Method not allowed' });

    const existing = await sql`SELECT id FROM operations WHERE id=${id}`;
    if (!existing.length) return sendJson(res, 404, { error: 'Operasi tidak ditemukan' });

    // Explicitly detach references first. This also fixes databases created
    // by older versions whose FK did not have ON DELETE SET NULL.
    await sql`UPDATE hailing_records SET ops_id=NULL, ops_name=NULL, updated_at=NOW() WHERE ops_id=${id}`;
    const result = await sql`DELETE FROM operations WHERE id=${id}`;
    return sendJson(res, 200, { ok: true, id, deleted: Number(result.count || 0) });
  } catch (e) {
    console.error('operation route error', e);
    return sendJson(res, e.status || 500, { error: e.message || 'Server error' });
  }
};

};

__modules["records/index"] = function(module, exports, require) {
const { sendJson, body, ensureInitialized, allRecords, saveRecord } = require('../_lib');
const { requireAuth } = require('../_auth');
module.exports = async (req,res)=>{res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');if(req.method==='OPTIONS')return res.status(204).end();try{await ensureInitialized();
    await requireAuth(req);if(req.method==='GET')return sendJson(res,200,await allRecords());if(req.method==='POST')return sendJson(res,201,await saveRecord(await body(req)));return sendJson(res,405,{error:'Method not allowed'});}catch(e){console.error(e);return sendJson(res,e.status||500,{error:e.message||'Server error'});}};

};

__modules["records/bulk-delete"] = function(module, exports, require) {
const { sendJson, body, ensureInitialized, sql } = require('../_lib');
const { requireAuth } = require('../_auth');
module.exports = async (req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return res.status(204).end();
  try{
    await ensureInitialized();
    await requireAuth(req);
    if(req.method!=='POST') return sendJson(res,405,{error:'Method not allowed'});
    const b=await body(req);
    const ids=Array.isArray(b.ids)?[...new Set(b.ids.map(String).filter(Boolean))]:[];
    if(!ids.length) return sendJson(res,400,{error:'Tidak ada ID yang dipilih'});
    let deleted=0;
    for(const id of ids){
      await sql`DELETE FROM vessels WHERE hailing_id=${id}`;
      const r=await sql`DELETE FROM hailing_records WHERE id=${id}`;
      deleted+=Number(r.count||0);
    }
    return sendJson(res,200,{ok:true,deleted});
  }catch(e){
    console.error(e);
    return sendJson(res,e.status||500,{error:e.message||'Server error'});
  }
};

};

__modules["operations/index"] = function(module, exports, require) {
const { sendJson, body, ensureInitialized, sql, makeId, now } = require('../_lib');
const { requireAuth } = require('../_auth');
module.exports = async (req,res)=>{res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');if(req.method==='OPTIONS')return res.status(204).end();try{await ensureInitialized();
    await requireAuth(req);if(req.method==='GET'){const rows=await sql`SELECT id,name,created_at AS "createdAt",updated_at AS "updatedAt" FROM operations ORDER BY created_at ASC`;return sendJson(res,200,rows);}if(req.method==='POST'){const b=await body(req);const name=String(b.name||'').trim();if(!name)return sendJson(res,400,{error:'Nama operasi wajib diisi'});const id=b.id||makeId(),t=now();await sql`INSERT INTO operations(id,name,created_at,updated_at) VALUES(${id},${name},${t},${t}) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,updated_at=EXCLUDED.updated_at`;return sendJson(res,201,{id,name,createdAt:t,updatedAt:t});}return sendJson(res,405,{error:'Method not allowed'});}catch(e){console.error(e);return sendJson(res,e.status||500,{error:e.message||'Server error'});}};

};

const routes = {
  "/health": "health",
  "/auth-login": "auth-login",
  "/auth-refresh": "auth-refresh",
  "/auth-logout": "auth-logout",
  "/auth-me": "auth-me",
  "/records": "records/index",
  "/records/bulk-delete": "records/bulk-delete",
  "/record": "record",
  "/operations": "operations/index",
  "/operation": "operation",
  "/import": "import"
};

function getPathname(req) {
  const raw = String(req.url || '/');
  try {
    const hinted = new URL(raw, 'http://localhost').searchParams.get('__route');
    if (hinted) {
      let p = String(hinted);
      if (!p.startsWith('/')) p = '/' + p;
      return p.replace(/\/$/, '') || '/';
    }
  } catch (_) {}
  let pathname;
  try { pathname = new URL(raw, 'http://localhost').pathname; }
  catch (_) { pathname = raw.split('?')[0] || '/'; }
  pathname = pathname.replace(/^\/api(?:\/index(?:\.js)?)?/, '') || '/';
  if (!pathname.startsWith('/')) pathname = '/' + pathname;
  return pathname;
}

function getQuery(req) {
  const raw = String(req.url || '/');
  try { return new URL(raw, 'http://localhost').searchParams; }
  catch (_) { return new URLSearchParams(raw.includes('?') ? raw.slice(raw.indexOf('?')) : ''); }
}

module.exports = async function handler(req, res) {
  const pathname = getPathname(req);
  const params = getQuery(req);
  req.query = Object.fromEntries(params.entries());
  const moduleId = routes[pathname];
  if (!moduleId) return sendJson(res, 404, { error: 'API endpoint tidak ditemukan', path: pathname });
  try {
    const handler = __load(moduleId);
    return await handler(req, res);
  } catch (e) {
    console.error('API dispatcher error:', e);
    return sendJson(res, e?.status || 500, { error: e?.message || 'Server error' });
  }
};
