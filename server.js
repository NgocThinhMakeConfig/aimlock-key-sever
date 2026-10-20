/* ============================================================ */
/* AIMLOCK KEY SERVER v7.2                                      */
/* ============================================================ */
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
// Đảm bảo độ dài >= 16 ký tự để ADMIN_READY = true
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'vietphi123_sieu_bao_mat_123'; 

const ADMIN_READY = ADMIN_TOKEN.length >= 16;

if (!process.env.ADMIN_TOKEN) {
  console.warn('⚠️  Bạn chưa set ADMIN_TOKEN trong Environment. Đang dùng token mặc định (nguy hiểm)!');
}
if (!ADMIN_READY) {
  console.error('❌ ADMIN_TOKEN quá ngắn (<16 ký tự) → API Admin bị khóa!');
}

/* ===== DATABASE ===== */
function buildDbConfig() {
  const raw = process.env.DATABASE_URL;
  if (!raw) return null;
  const u = new URL(raw);
  // Xóa tham số SSL trong URL để cấu hình ssl bên dưới không bị ghi đè
  u.searchParams.delete('sslmode');
  u.searchParams.delete('ssl');

  // Internal URL của Render (hostname không có dấu chấm) không cần SSL.
  // External URL (…render.com) cần SSL. Có thể ép bằng DB_SSL=true/false.
  let useSsl = u.hostname.includes('.');
  if (process.env.DB_SSL === 'true') useSsl = true;
  if (process.env.DB_SSL === 'false') useSsl = false;

  return {
    connectionString: u.toString(),
    ssl: useSsl ? { rejectUnauthorized: false } : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };
}

let dbConfig = null;
try {
  dbConfig = buildDbConfig();
} catch (e) {
  console.error('❌ DATABASE_URL không đúng định dạng:', e.message);
}
if (!dbConfig) console.error('⚠️  Chưa có DATABASE_URL hợp lệ → API key sẽ báo LỖI SERVER cho tới khi cấu hình.');

const pool = new Pool(dbConfig || { connectionString: 'postgresql://invalid:invalid@127.0.0.1:1/invalid' });
pool.on('error', (err) => console.error('❌ Lỗi pool idle:', err.message));

let dbReady = false;
// Tự kết nối lại nếu DB chưa sẵn sàng (Render hay khởi động DB chậm hơn web)
async function connectWithRetry() {
  if (!dbConfig) return;
  for (let attempt = 1; !dbReady; attempt++) {
    try {
      await initDB();
      dbReady = true;
    } catch (err) {
      console.error(`❌ Lỗi DB (lần ${attempt}):`, err.message, '| code:', err.code);
      if (err.code === '28P01') console.error('👉 Sai mật khẩu. Kiểm tra DATABASE_URL.');
      else if (err.code === 'ENOTFOUND') console.error('👉 Sai hostname. Dùng Internal Database URL nếu cùng region.');
      await new Promise((r) => setTimeout(r, Math.min(5000 * attempt, 30000)));
    }
  }
}

async function initDB() {
  console.log('⏳ Đang kết nối tới Database...');
  await pool.query('SELECT 1');
  console.log('✅ Kết nối Database thành công!');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      key_code TEXT PRIMARY KEY,
      status TEXT DEFAULT 'unused',
      duration_days INTEGER DEFAULT 30,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      activated_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ,
      device_id TEXT,
      last_seen TIMESTAMPTZ,
      note TEXT
    );
  `);
  console.log('✅ Bảng keys đã sẵn sàng!');
}

/* ===== CORS ===== */
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({ limit: '10kb' }));

/* ===== RATE LIMIT đơn giản (chống dò key / brute-force token) ===== */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    const now = Date.now();
    let h = hits.get(req.ip);
    if (!h || h.reset < now) {
      h = { count: 0, reset: now + windowMs };
      hits.set(req.ip, h);
    }
    h.count++;
    if (h.count > max) {
      return res.status(429).json({ valid: false, success: false, error: 'QUÁ NHIỀU YÊU CẦU, THỬ LẠI SAU' });
    }
    next();
  };
}
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
const heartbeatLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
const adminLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

/* ===== HELPERS ===== */
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateKey(prefix = 'AIM') {
  const parts = [];
  for (let p = 0; p < 4; p++) {
    let part = '';
    for (let i = 0; i < 4; i++) part += KEY_CHARS[crypto.randomInt(KEY_CHARS.length)];
    parts.push(part);
  }
  return prefix + '-' + parts.join('-');
}

function normalizeKey(key) {
  return typeof key === 'string' ? key.trim().toUpperCase() : '';
}

function isValidKeyFormat(key) {
  return /^[A-Z0-9-]{10,40}$/.test(key);
}

function isValidDeviceId(id) {
  return typeof id === 'string' && id.length >= 5 && id.length <= 200;
}

/* ===== Chặn sớm khi DB chưa sẵn sàng ===== */
app.use('/api', (req, res, next) => {
  if (!dbReady) return res.status(503).json({ valid: false, success: false, error: 'DATABASE ĐANG KHỞI ĐỘNG, THỬ LẠI SAU' });
  next();
});

/* ===== HEALTH CHECK ===== */
app.get('/', (req, res) => {
  res.json({ name: 'AIMLOCK KEY SERVER', version: '7.2.0', status: 'online', db: dbReady, time: new Date().toISOString() });
});

/* ===== VERIFY KEY ===== */
app.post('/api/verify', verifyLimiter, async (req, res) => {
  const { key, deviceId } = req.body || {};
  const keyCode = normalizeKey(key);

  if (!isValidKeyFormat(keyCode)) return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
  if (!isValidDeviceId(deviceId)) return res.json({ valid: false, error: 'THIẾU DEVICE ID' });

  try {
    // 1) Kích hoạt nguyên tử: chỉ 1 request thắng nếu nhiều thiết bị cùng kích hoạt
    const act = await pool.query(
      `UPDATE keys
         SET status = 'active',
             activated_at = NOW(),
             expires_at = NOW() + make_interval(days => COALESCE(duration_days, 30)),
             device_id = $1,
             last_seen = NOW()
       WHERE key_code = $2 AND status = 'unused'
       RETURNING expires_at`,
      [deviceId, keyCode]
    );
    if (act.rowCount === 1) {
      return res.json({
        valid: true,
        message: 'KÍCH HOẠT THÀNH CÔNG',
        key: keyCode,
        expiresAt: act.rows[0].expires_at,
      });
    }

    // 2) Key đã tồn tại từ trước → kiểm tra
    const result = await pool.query('SELECT * FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });
    const record = result.rows[0];

    if (record.status === 'banned') return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });

    if (record.status === 'expired' || (record.expires_at && new Date(record.expires_at) < new Date())) {
      if (record.status !== 'expired') {
        await pool.query(`UPDATE keys SET status = 'expired' WHERE key_code = $1`, [keyCode]);
      }
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // 3) Gắn thiết bị nguyên tử (kể cả sau khi admin reset device_id = NULL)
    const bind = await pool.query(
      `UPDATE keys
         SET device_id = COALESCE(device_id, $1), last_seen = NOW()
       WHERE key_code = $2
       RETURNING device_id, expires_at`,
      [deviceId, keyCode]
    );
    const row = bind.rows[0];
    if (row.device_id !== deviceId) {
      return res.json({ valid: false, error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC' });
    }

    return res.json({ valid: true, message: 'XÁC THỰC THÀNH CÔNG', key: keyCode, expiresAt: row.expires_at });
  } catch (e) {
    console.error('Verify error:', e.message);
    res.status(500).json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== HEARTBEAT ===== */
app.post('/api/heartbeat', heartbeatLimiter, async (req, res) => {
  const { key, deviceId } = req.body || {};
  const keyCode = normalizeKey(key);
  if (!isValidKeyFormat(keyCode) || !isValidDeviceId(deviceId)) return res.json({ valid: false });

  try {
    const result = await pool.query('SELECT * FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });

    const record = result.rows[0];
    if (record.status === 'banned') return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    if (record.status !== 'active') return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      await pool.query(`UPDATE keys SET status = 'expired' WHERE key_code = $1`, [keyCode]);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }
    if (record.device_id !== deviceId) return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });

    await pool.query('UPDATE keys SET last_seen = NOW() WHERE key_code = $1', [keyCode]);
    return res.json({ valid: true, expiresAt: record.expires_at });
  } catch (e) {
    console.error('Heartbeat error:', e.message);
    return res.status(500).json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== ADMIN AUTH (chỉ nhận qua header, so sánh an toàn thời gian) ===== */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAdmin(req, res, next) {
  if (!ADMIN_READY) return res.status(503).json({ success: false, error: 'ADMIN CHƯA ĐƯỢC CẤU HÌNH' });
  const token = req.headers['x-admin-token'];
  if (!token || !safeEqual(token, ADMIN_TOKEN)) {
    return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
  }
  next();
}

const admin = [adminLimiter, requireAdmin];

/* ===== ADMIN: TẠO KEY ===== */
app.post('/api/admin/create', admin, async (req, res) => {
  const { count, duration_days, prefix, note } = req.body || {};
  const numKeys = Math.max(1, Math.min(parseInt(count) || 1, 100));
  const duration = Math.max(1, Math.min(parseInt(duration_days) || 30, 3650));
  const keyPrefix = (String(prefix || 'AIM').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)) || 'AIM';
  const createdKeys = [];

  try {
    while (createdKeys.length < numKeys) {
      const newKey = generateKey(keyPrefix);
      const r = await pool.query(
        `INSERT INTO keys (key_code, duration_days, note) VALUES ($1, $2, $3)
         ON CONFLICT (key_code) DO NOTHING`,
        [newKey, duration, note ? String(note).slice(0, 200) : null]
      );
      if (r.rowCount === 1) createdKeys.push(newKey);
    }
    res.json({ success: true, count: createdKeys.length, keys: createdKeys });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI TẠO KEY' });
  }
});

/* ===== ADMIN: DANH SÁCH KEY ===== */
app.post('/api/admin/list', admin, async (req, res) => {
  const { status, limit } = req.body || {};
  try {
    const params = [];
    let query = 'SELECT * FROM keys';
    if (status && status !== 'all') {
      query += ' WHERE status = $1';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
    params.push(Math.max(1, Math.min(parseInt(limit) || 100, 500)));

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rowCount, keys: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== ADMIN: THỐNG KÊ ===== */
app.post('/api/admin/stats', admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status = 'active') AS active,
        COUNT(*) FILTER (WHERE status = 'banned') AS banned,
        COUNT(*) FILTER (WHERE status = 'expired') AS expired,
        COUNT(*) FILTER (WHERE status = 'unused') AS unused
      FROM keys
    `);
    const stats = result.rows[0];
    Object.keys(stats).forEach((k) => (stats[k] = parseInt(stats[k])));
    res.json({ success: true, stats });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== ADMIN: ĐỔI STATUS ===== */
app.post('/api/admin/set-status', admin, async (req, res) => {
  const { key, status } = req.body || {};
  const validStatus = ['unused', 'active', 'expired', 'banned'];
  if (!validStatus.includes(status)) return res.status(400).json({ success: false, error: 'STATUS KHÔNG HỢP LỆ' });

  try {
    const result = await pool.query('UPDATE keys SET status = $1 WHERE key_code = $2', [status, normalizeKey(key)]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== ADMIN: XÓA KEY ===== */
app.post('/api/admin/delete', admin, async (req, res) => {
  const { key } = req.body || {};
  try {
    const result = await pool.query('DELETE FROM keys WHERE key_code = $1', [normalizeKey(key)]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== ADMIN: RESET DEVICE ===== */
app.post('/api/admin/reset-device', admin, async (req, res) => {
  const { key } = req.body || {};
  try {
    const result = await pool.query(
      'UPDATE keys SET device_id = NULL, last_seen = NULL WHERE key_code = $1',
      [normalizeKey(key)]
    );
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== ADMIN: GIA HẠN (nguyên tử trong SQL) ===== */
app.post('/api/admin/extend', admin, async (req, res) => {
  const { key, days } = req.body || {};
  const extendDays = Math.max(1, Math.min(parseInt(days) || 30, 3650));

  try {
    const result = await pool.query(
      `UPDATE keys
         SET expires_at = GREATEST(COALESCE(expires_at, NOW()), NOW()) + make_interval(days => $1),
             status = 'active',
             activated_at = COALESCE(activated_at, NOW())
       WHERE key_code = $2
       RETURNING expires_at`,
      [extendDays, normalizeKey(key)]
    );
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true, newExpiry: result.rows[0].expires_at });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'LỖI' });
  }
});

/* ===== 404 ===== */
app.use((req, res) => res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' }));

/* ===== ERROR HANDLER (JSON lỗi cú pháp, body quá lớn, ...) ===== */
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ valid: false, success: false, error: 'JSON KHÔNG HỢP LỆ' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ valid: false, success: false, error: 'DỮ LIỆU QUÁ LỚN' });
  }
  console.error('Unhandled error:', err && err.message);
  res.status(500).json({ valid: false, success: false, error: 'LỖI SERVER' });
});

/* ===== START ===== */
const server = app.listen(PORT, () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v7.2');
  console.log('📡 Port:', PORT);
  console.log('==========================================');
});

connectWithRetry();

// Mỗi 10 phút: đánh dấu key đã hết hạn (chỉ đổi status, KHÔNG xóa key)
setInterval(async () => {
  if (!dbReady) return;
  try {
    const r = await pool.query(`UPDATE keys SET status = 'expired' WHERE status = 'active' AND expires_at < NOW()`);
    if (r.rowCount) console.log(`🧹 Đã đánh dấu hết hạn ${r.rowCount} key`);
  } catch (e) {
    console.error('Cleanup error:', e.message);
  }
}, 10 * 60 * 1000).unref();

function shutdown() {
  console.log('⏹ Đang tắt server...');
  server.close(() => pool.end().catch(() => {}).finally(() => process.exit(0)));
  setTimeout(() => process.exit(0), 8000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (r) => console.error('Unhandled rejection:', r));
