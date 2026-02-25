const express = require('express');
const initSqlJs = require('sql.js');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 8742;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const app = express();
let db;

const DB_PATH = path.join(__dirname, 'db', 'stamina.db');

// ==================== DATABASE ====================
async function initDB() {
  const SQL = await initSqlJs();
  const dbDir = path.join(__dirname, 'db');
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nickname TEXT NOT NULL,
      auth_type TEXT NOT NULL DEFAULT 'guest',
      auth_id TEXT,
      avatar_url TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(auth_type, auth_id)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      lesson TEXT,
      layout TEXT DEFAULT 'ru',
      speed INTEGER DEFAULT 0,
      errors INTEGER DEFAULT 0,
      total_keys INTEGER DEFAULT 0,
      accuracy INTEGER DEFAULT 0,
      time_seconds INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_speed ON sessions(speed DESC)');
  saveDB();
}

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Auto-save every 30 seconds
setInterval(() => { if (db) saveDB(); }, 30000);

// Helper to run queries
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const row = stmt.getAsObject(); stmt.free(); return row; }
  stmt.free(); return null;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free(); return rows;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  const result = db.exec("SELECT last_insert_rowid() as id");
  const lastId = result.length > 0 ? result[0].values[0][0] : 0;
  saveDB();
  return { lastId };
}

// ==================== MIDDLEWARE ====================
// SECURITY FIX: Limit request body size to prevent DoS via large payloads
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// SECURITY FIX: Set basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// SECURITY FIX: Block access to sensitive files before static middleware.
// express.static(__dirname) would otherwise expose server.js, package.json,
// package-lock.json, db/stamina.db, node_modules/, and any .env files.
const BLOCKED_PATHS = ['/server.js', '/package.json', '/package-lock.json', '/.env', '/.gitignore'];
const BLOCKED_PREFIXES = ['/db/', '/node_modules/', '/.'];
app.use((req, res, next) => {
  const urlPath = decodeURIComponent(req.path).toLowerCase();
  if (BLOCKED_PATHS.includes(urlPath) || BLOCKED_PREFIXES.some(p => urlPath.startsWith(p))) {
    return res.status(404).send('Not found');
  }
  next();
});
app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'deny' }));

function authMiddleware(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) { req.user = null; return next(); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = dbGet('SELECT id, nickname, auth_type, avatar_url, created_at FROM users WHERE id = ?', [decoded.userId]);
  } catch {
    req.user = null;
  }
  next();
}

app.use('/api', authMiddleware);

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function issueToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '90d' });
}

// SECURITY FIX: Centralized cookie options; adds 'secure' flag in production
function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    maxAge: 90 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    secure: IS_PRODUCTION // SECURITY FIX: send cookie only over HTTPS in production
  });
}

// SECURITY FIX: Sanitize nickname -- strip control characters and null bytes
function sanitizeNickname(raw) {
  if (typeof raw !== 'string') return '';
  // Remove null bytes, control characters (except space), and trim
  return raw.replace(/[\x00-\x1f\x7f]/g, '').trim();
}

// SECURITY FIX: Validate URL is a safe HTTPS URL (for avatar_url)
function sanitizeAvatarUrl(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') return url;
    return null; // Reject non-HTTPS URLs (http:, javascript:, data:, etc.)
  } catch {
    return null;
  }
}

// ==================== AUTH ROUTES ====================

// Guest login
app.post('/api/auth/guest', (req, res) => {
  const { nickname } = req.body;
  // SECURITY FIX: Sanitize nickname to remove control characters
  const cleanNick = sanitizeNickname(nickname);
  if (!cleanNick || cleanNick.length < 1 || cleanNick.length > 30) {
    return res.status(400).json({ error: 'Nickname must be 1-30 characters' });
  }
  const guestId = 'guest_' + crypto.randomBytes(8).toString('hex');
  const { lastId } = dbRun('INSERT INTO users (nickname, auth_type, auth_id) VALUES (?, ?, ?)', [cleanNick, 'guest', guestId]);
  const user = dbGet('SELECT id, nickname, auth_type, avatar_url, created_at FROM users WHERE id = ?', [lastId]);
  const token = issueToken(lastId);
  setAuthCookie(res, token);
  // SECURITY FIX: Do not return token in JSON body; it is in the httpOnly cookie
  res.json({ user });
});

// Telegram login
app.post('/api/auth/telegram', (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(500).json({ error: 'Telegram not configured' });
  const data = req.body;
  // SECURITY FIX: Validate hash and auth_date types before using them
  if (!data.hash || typeof data.hash !== 'string') return res.status(400).json({ error: 'Missing hash' });
  const authDate = Number(data.auth_date);
  if (!Number.isFinite(authDate)) return res.status(400).json({ error: 'Invalid auth_date' });

  const { hash, ...authData } = data;
  // SECURITY FIX: Only include string/number values in check string to prevent [object Object] injection
  const checkString = Object.keys(authData).sort()
    .filter(k => typeof authData[k] === 'string' || typeof authData[k] === 'number')
    .map(k => `${k}=${authData[k]}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(TELEGRAM_BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');
  // SECURITY FIX: Use timing-safe comparison to prevent timing attacks on HMAC
  // Validate hash is a valid hex string of the expected length before comparing
  if (!/^[0-9a-f]{64}$/i.test(hash) || !crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(hash, 'hex'))) {
    return res.status(401).json({ error: 'Invalid Telegram auth' });
  }
  // SECURITY FIX: Use validated numeric auth_date for expiry check
  if (Date.now() / 1000 - authDate > 86400) return res.status(401).json({ error: 'Auth expired' });

  const authId = 'tg_' + data.id;
  let user = dbGet('SELECT * FROM users WHERE auth_type = ? AND auth_id = ?', ['telegram', authId]);
  if (!user) {
    const name = sanitizeNickname(data.first_name + (data.last_name ? ' ' + data.last_name : ''));
    // SECURITY FIX: Sanitize avatar URL to only allow HTTPS
    const { lastId } = dbRun('INSERT INTO users (nickname, auth_type, auth_id, avatar_url) VALUES (?, ?, ?, ?)', [name || 'Telegram User', 'telegram', authId, sanitizeAvatarUrl(data.photo_url)]);
    user = dbGet('SELECT id, nickname, auth_type, avatar_url, created_at FROM users WHERE id = ?', [lastId]);
  }
  const token = issueToken(user.id);
  setAuthCookie(res, token);
  // SECURITY FIX: Do not return token in JSON body
  res.json({ user });
});

// Google login
app.post('/api/auth/google', async (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Google not configured' });
  const { credential } = req.body;
  // SECURITY FIX: Validate credential is a string before using it
  if (!credential || typeof credential !== 'string') return res.status(400).json({ error: 'Missing credential' });
  try {
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    if (!response.ok) return res.status(401).json({ error: 'Invalid Google token' });
    const payload = await response.json();
    if (payload.aud !== GOOGLE_CLIENT_ID) return res.status(401).json({ error: 'Wrong audience' });

    const authId = 'google_' + payload.sub;
    let user = dbGet('SELECT * FROM users WHERE auth_type = ? AND auth_id = ?', ['google', authId]);
    if (!user) {
      const name = sanitizeNickname(payload.name || payload.email);
      const { lastId } = dbRun('INSERT INTO users (nickname, auth_type, auth_id, avatar_url) VALUES (?, ?, ?, ?)',
        [name || 'Google User', 'google', authId, sanitizeAvatarUrl(payload.picture)]);
      user = dbGet('SELECT id, nickname, auth_type, avatar_url, created_at FROM users WHERE id = ?', [lastId]);
    }
    const token = issueToken(user.id);
    setAuthCookie(res, token);
    // SECURITY FIX: Do not return token in JSON body
    res.json({ user });
  } catch {
    res.status(500).json({ error: 'Google auth failed' });
  }
});

// Current user
app.get('/api/auth/me', (req, res) => {
  res.json({ user: req.user || null });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// Update nickname
app.post('/api/auth/nickname', requireAuth, (req, res) => {
  const { nickname } = req.body;
  // SECURITY FIX: Sanitize nickname to remove control characters
  const cleanNick = sanitizeNickname(nickname);
  if (!cleanNick || cleanNick.length < 1 || cleanNick.length > 30) {
    return res.status(400).json({ error: 'Nickname must be 1-30 characters' });
  }
  dbRun('UPDATE users SET nickname = ? WHERE id = ?', [cleanNick, req.user.id]);
  res.json({ user: dbGet('SELECT id, nickname, auth_type, avatar_url, created_at FROM users WHERE id = ?', [req.user.id]) });
});

// ==================== STATS ====================

// Save session
app.post('/api/stats/session', requireAuth, (req, res) => {
  const { lesson, layout, speed, errors, total_keys, accuracy, time_seconds } = req.body;
  if (typeof speed !== 'number' || speed < 0 || speed > 2000) return res.status(400).json({ error: 'Invalid speed' });
  if (typeof time_seconds !== 'number' || time_seconds < 1 || time_seconds > 86400) return res.status(400).json({ error: 'Invalid time' });
  // SECURITY FIX: Validate and bound all numeric fields to prevent abuse
  const safeErrors = typeof errors === 'number' ? Math.max(0, Math.min(Math.round(errors), 100000)) : 0;
  const safeTotalKeys = typeof total_keys === 'number' ? Math.max(0, Math.min(Math.round(total_keys), 100000)) : 0;
  const safeAccuracy = typeof accuracy === 'number' ? Math.max(0, Math.min(Math.round(accuracy), 100)) : 0;
  // SECURITY FIX: Truncate lesson and layout strings to prevent oversized storage
  const safeLesson = typeof lesson === 'string' ? lesson.substring(0, 200) : '?';
  const safeLayout = typeof layout === 'string' ? layout.substring(0, 10) : 'ru';
  dbRun('INSERT INTO sessions (user_id, lesson, layout, speed, errors, total_keys, accuracy, time_seconds) VALUES (?,?,?,?,?,?,?,?)',
    [req.user.id, safeLesson || '?', safeLayout || 'ru', Math.round(speed), safeErrors, safeTotalKeys, safeAccuracy, Math.round(time_seconds)]);
  res.json({ ok: true });
});

// User stats
app.get('/api/stats/me', requireAuth, (req, res) => {
  const summary = dbGet(`
    SELECT COUNT(*) as total_sessions, COALESCE(SUM(time_seconds),0) as total_time,
           COALESCE(SUM(total_keys),0) as total_keys, ROUND(COALESCE(AVG(speed),0)) as avg_speed,
           COALESCE(MAX(speed),0) as best_speed, ROUND(COALESCE(AVG(accuracy),0)) as avg_accuracy
    FROM sessions WHERE user_id = ?
  `, [req.user.id]);
  const sessions = dbAll('SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  res.json({ summary, sessions });
});

// Leaderboard
app.get('/api/stats/leaderboard', (req, res) => {
  const board = dbAll(`
    SELECT u.nickname, u.avatar_url, MAX(s.speed) as best_speed, ROUND(AVG(s.speed)) as avg_speed, COUNT(s.id) as sessions
    FROM users u JOIN sessions s ON u.id = s.user_id
    GROUP BY u.id ORDER BY best_speed DESC LIMIT 30
  `);
  res.json({ leaderboard: board });
});

// ==================== START ====================
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Stamina server running on http://localhost:${PORT}`);
    console.log(`Telegram auth: ${TELEGRAM_BOT_TOKEN ? 'configured' : 'not configured (set TELEGRAM_BOT_TOKEN)'}`);
    console.log(`Google auth: ${GOOGLE_CLIENT_ID ? 'configured' : 'not configured (set GOOGLE_CLIENT_ID)'}`);
  });
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
