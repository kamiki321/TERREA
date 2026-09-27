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
let sqlClient = null;
function getSql() {
  if (sqlClient) return sqlClient;
  const databaseUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL || process.env.NEON_DATABASE_URL;
  if (!databaseUrl) throw new Error('Database URL belum dikonfigurasi. Tambahkan DATABASE_URL di Vercel Environment Variables.');
  sqlClient = neon(databaseUrl);
  return sqlClient;
}
// Lazy SQL client: authentication can work without touching Neon.
async function sql(strings, ...values) {
  return getSql()(strings, ...values);
}
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

// DATABASE-BACKED AUTHENTICATION
// Users and refresh sessions are stored in Neon PostgreSQL.
// The application still uses a single Vercel Serverless Function.
const ACCESS_TTL_SECONDS = 60 * 60; // 1 hour
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const COOKIE_NAME = 'terrea_refresh_token';
const PASSWORD_RULE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

function authError(message, status = 401, code = 'AUTH_ERROR') {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function validatePassword(password) {
  return typeof password === 'string' && PASSWORD_RULE.test(password);
}

function passwordRuleMessage() {
  return 'Password minimal 8 karakter, mengandung 1 huruf uppercase, 1 angka, dan 1 karakter special.';
}

function getConfiguredUsername() {
  return String(process.env.DEFAULT_ADMIN_USERNAME || 'kujang642').trim();
}

function getConfiguredPassword() {
  return String(process.env.DEFAULT_ADMIN_PASSWORD || 'Kujang642Satkat1#');
}

function getJwtSecret() {
  const secret = String(process.env.AUTH_JWT_SECRET || '').trim();
  if (secret.length < 32) {
    throw authError('AUTH_JWT_SECRET belum dikonfigurasi atau kurang dari 32 karakter.', 500, 'AUTH_SECRET_MISSING');
  }
  return secret;
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const signature = crypto.createHmac('sha256', getJwtSecret()).update(data).digest('base64url');
  return `${data}.${signature}`;
}

function verifyToken(token, expectedType) {
  try {
    if (typeof token !== 'string' || !token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, signature] = parts;
    const expected = crypto.createHmac('sha256', getJwtSecret()).update(`${header}.${body}`).digest('base64url');
    if (signature.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= now) return null;
    if (expectedType && payload.type !== expectedType) return null;
    if (!payload.sub || !payload.username) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function createAccessToken(user) {
  const now = Math.floor(Date.now() / 1000);
  return signToken({
    type: 'access',
    sub: String(user.id),
    username: user.username,
    iat: now,
    exp: now + ACCESS_TTL_SECONDS
  });
}

function createRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt}$${derived.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const [, salt, hashHex] = parts;
    const actual = crypto.scryptSync(String(password), salt, hashHex.length / 2);
    const expected = Buffer.from(hashHex, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}

function parseCookies(req) {
  const raw = req.headers?.cookie || '';
  const out = {};
  raw.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) {
      try { out[k] = decodeURIComponent(v); } catch (_) { out[k] = v; }
    }
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
}

async function ensureDefaultUser() {
  const username = getConfiguredUsername();
  const configuredPassword = getConfiguredPassword();
  const rows = await sql`SELECT id, username, password FROM "user" WHERE username=${username} LIMIT 1`;
  if (rows.length) return rows[0];

  const passwordHash = hashPassword(configuredPassword);
  const inserted = await sql`INSERT INTO "user" (username, password) VALUES (${username}, ${passwordHash}) RETURNING id, username, password`;
  return inserted[0];
}

async function findUserByUsername(username) {
  const rows = await sql`SELECT id, username, password FROM "user" WHERE username=${username} LIMIT 1`;
  return rows[0] || null;
}

async function issueSession(user) {
  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken();
  const tokenHash = hashRefreshToken(refreshToken);
  const sessionId = crypto.randomBytes(18).toString('base64url');
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();

  await sql`INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,last_used_at)
    VALUES(${sessionId},${Number(user.id)},${tokenHash},NOW(),${expiresAt},NOW())`;

  return { accessToken, refreshToken, sessionId };
}

async function rotateRefreshSession(refreshToken) {
  const tokenHash = hashRefreshToken(refreshToken);
  const rows = await sql`
    SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at,
           u.username
    FROM user_sessions s
    JOIN "user" u ON u.id=s.user_id
    WHERE s.token_hash=${tokenHash}
    LIMIT 1`;

  if (!rows.length) throw authError('Refresh token tidak ditemukan.', 401, 'REFRESH_SESSION_NOT_FOUND');
  const session = rows[0];
  if (session.revoked_at) throw authError('Session sudah dicabut. Silakan login kembali.', 401, 'REFRESH_SESSION_REVOKED');
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await sql`UPDATE user_sessions SET revoked_at=NOW() WHERE id=${session.session_id}`;
    throw authError('Session sudah berakhir. Silakan login kembali.', 401, 'REFRESH_SESSION_EXPIRED');
  }

  await sql`UPDATE user_sessions SET revoked_at=NOW(), last_used_at=NOW() WHERE id=${session.session_id}`;
  const user = { id: session.user_id, username: session.username };
  const next = await issueSession(user);
  return { ...next, userId: user.id, username: user.username };
}

async function revokeRefreshSession(refreshToken) {
  if (!refreshToken) return;
  const tokenHash = hashRefreshToken(refreshToken);
  await sql`UPDATE user_sessions SET revoked_at=NOW(), last_used_at=NOW() WHERE token_hash=${tokenHash} AND revoked_at IS NULL`;
}

async function requireAuth(req) {
  const auth = String(req.headers?.authorization || '');
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const payload = verifyToken(token, 'access');
  if (!payload) throw authError('Sesi login tidak valid atau sudah berakhir.', 401, 'ACCESS_TOKEN_INVALID');
  return { id: Number(payload.sub), username: payload.username };
}

async function cleanupExpiredSessions() {
  await sql`DELETE FROM user_sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL`;
}

module.exports = {
  COOKIE_NAME, ACCESS_TTL_SECONDS, REFRESH_TTL_SECONDS,
  validatePassword, passwordRuleMessage,
  parseCookies, setRefreshCookie, clearRefreshCookie,
  ensureAuthDatabase, ensureDefaultUser, findUserByUsername,
  issueSession, rotateRefreshSession, revokeRefreshSession,
  requireAuth, cleanupExpiredSessions,
  getConfiguredUsername, getConfiguredPassword, verifyPassword
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
const { validatePassword, passwordRuleMessage, issueSession, setRefreshCookie, ensureAuthDatabase, ensureDefaultUser, findUserByUsername, verifyPassword } = require('./_auth');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return sendJson(res, 204, {});
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed' });

  try {
    const b = await body(req);
    const username = String(b.username || '').trim();
    const password = typeof b.password === 'string' ? b.password : '';
    if (!username || !password) return sendJson(res, 400, { error: 'Username dan password wajib diisi.', code: 'MISSING_CREDENTIALS' });
    if (!validatePassword(password)) return sendJson(res, 400, { error: passwordRuleMessage(), code: 'PASSWORD_FORMAT_INVALID' });

    // Authentication is stored in Neon. On a fresh database, create the auth
    // tables and seed the configured administrator account exactly once.
    await ensureAuthDatabase();
    let user = await findUserByUsername(username);
    if (!user && username === String(process.env.DEFAULT_ADMIN_USERNAME || 'kujang642').trim()) {
      user = await ensureDefaultUser();
    }

    if (!user || !verifyPassword(password, user.password)) {
      return sendJson(res, 401, { error: 'Username atau password salah.', code: 'INVALID_CREDENTIALS' });
    }

    const session = await issueSession({ id: user.id, username: user.username });
    setRefreshCookie(res, session.refreshToken);
    return sendJson(res, 200, {
      ok: true,
      accessToken: session.accessToken,
      user: { id: user.id, username: user.username }
    });
  } catch (e) {
    console.error('auth login error:', e);
    return sendJson(res, e.status || 500, { error: e.message || 'Login gagal.', code: e.code || 'AUTH_LOGIN_ERROR' });
  }
};
};

__modules["auth-refresh"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { parseCookies, rotateRefreshSession, setRefreshCookie, clearRefreshCookie } = require('./_auth');
module.exports = async (req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return sendJson(res,204,{});
  if(req.method!=='POST') return sendJson(res,405,{error:'Method not allowed'});
  try{
    const token=parseCookies(req).terrea_refresh_token;
    if(!token){ clearRefreshCookie(res); return sendJson(res,401,{error:'Belum login.',code:'NO_REFRESH_TOKEN'}); }
    const session=await rotateRefreshSession(token);
    setRefreshCookie(res,session.refreshToken);
    return sendJson(res,200,{ok:true,accessToken:session.accessToken,user:{id:session.userId,username:session.username}});
  }catch(e){
    console.error('auth refresh error:', e);
    clearRefreshCookie(res);
    return sendJson(res,e.status||500,{error:e.message||'Session tidak valid.',code:e.code||'AUTH_REFRESH_ERROR'});
  }
};
};

__modules["auth-logout"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { parseCookies, clearRefreshCookie, revokeRefreshSession } = require('./_auth');
module.exports=async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS')return sendJson(res,204,{});
  if(req.method!=='POST')return sendJson(res,405,{error:'Method not allowed'});
  try {
    await revokeRefreshSession(parseCookies(req).terrea_refresh_token);
  } catch (e) {
    console.error('auth logout error:', e);
  }
  clearRefreshCookie(res);
  return sendJson(res,200,{ok:true});
};
};

__modules["auth-me"] = function(module, exports, require) {
const { sendJson } = require('./_lib');
const { requireAuth } = require('./_auth');
module.exports=async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if(req.method==='OPTIONS') return sendJson(res,204,{});
  if(req.method!=='GET') return sendJson(res,405,{error:'Method not allowed'});
  try{
    const user=await requireAuth(req);
    return sendJson(res,200,{ok:true,user});
  }catch(e){
    return sendJson(res,e.status||401,{error:e.message||'Unauthorized',code:'AUTH_ME_ERROR'});
  }
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

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
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
