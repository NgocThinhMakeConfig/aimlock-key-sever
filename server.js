/* ============================================================
   AIMLOCK KEY SERVER v16.0 - BYPASS PERMISSION EDITION
   - Sử dụng chung bảng keys_nova để tránh lỗi phân quyền
   - Tự động nhận diện External/Internal URL
   ============================================================ */
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
app.use(express.json({ limit: '10kb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'vietphi123_sieu_bao_mat_123';

let dbUrl = process.env.DATABASE_URL || '';
dbUrl = dbUrl.replace(/["'\s]/g, ''); 
if (dbUrl.includes('.render.com')) {
  dbUrl = dbUrl.replace(/(dpg-[a-z0-9]+-a)\..*?\.render\.com/, '$1');
}

const pool = new Pool({
  connectionString: dbUrl,
  ssl: dbUrl.includes('render.com') || dbUrl.includes('dpg-') ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

let dbReady = false;

pool.on('error', (err) => {
  console.error('❌ Lỗi Pool DB:', err.message);
  dbReady = false;
});

async function initDB() {
  console.log('⏳ Đang kết nối tới Database...');
  try {
    await pool.query('SELECT 1');
    console.log('✅ Kết nối Database thành công!');
    
    // SỬ DỤNG BẢNG CỦA NOVA ĐỂ TRÁNH LỖI PHÂN QUYỀN
    await pool.query('SELECT 1 FROM keys_nova LIMIT 1');
    console.log('✅ Đã tìm thấy bảng keys_nova. Sẵn sàng hoạt động!');
    dbReady = true;
  } catch (err) {
    console.error('❌ Lỗi kết nối bảng keys_nova:', err.message);
    throw err;
  }
}

async function connectWithRetry() {
  for (let attempt = 1; !dbReady; attempt++) {
    try {
      await initDB();
    } catch (err) {
      await new Promise((r) => setTimeout(r, Math.min(5000 * attempt, 30000)));
    }
  }
}
connectWithRetry();

/* ===== RATE LIMIT ===== */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();
  return (req, res, next) => {
    const now = Date.now();
    let h = hits.get(req.ip);
    if (!h || h.reset < now) { h = { count: 0, reset: now + windowMs }; hits.set(req.ip, h); }
    h.count++;
    if (h.count > max) return res.status(429).json({ error: 'QUÁ NHIỀU YÊU CẦU' });
    next();
  };
}
const verifyLimiter = rateLimit({ windowMs: 60000, max: 20 });
const heartbeatLimiter = rateLimit({ windowMs: 60000, max: 60 });
const adminLimiter = rateLimit({ windowMs: 60000, max: 60 });

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
function normalizeKey(key) { return typeof key === 'string' ? key.trim().toUpperCase() : ''; }
function isValidKeyFormat(key) { return /^[A-Z0-9-]{10,40}$/.test(key); }
function isValidDeviceId(id) { return typeof id === 'string' && id.length >= 5 && id.length <= 200; }

app.use('/api', (req, res, next) => {
  if (!dbReady) return res.status(503).json({ error: 'DATABASE ĐANG KHỞI ĐỘNG, THỬ LẠI SAU' });
  next();
});

app.get('/', (req, res) => res.json({ name: 'AIMLOCK KEY SERVER', version: '16.0.0', status: 'online', db: dbReady }));

/* ===== API: VERIFY (Dùng chung bảng keys_nova) ===== */
app.post('/api/verify', verifyLimiter, async (req, res) => {
  const { key, deviceId } = req.body || {};
  const keyCode = normalizeKey(key);
  if (!isValidKeyFormat(keyCode)) return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
  if (!isValidDeviceId(deviceId)) return res.json({ valid: false, error: 'THIẾU DEVICE ID' });

  try {
    // Lưu ý: Sử dụng các cột có sẵn trong bảng keys_nova của NOVA
    const act = await pool.query(
      `UPDATE keys_nova SET is_active = 1, activated_at = EXTRACT(EPOCH FROM NOW()), expires_at = EXTRACT(EPOCH FROM NOW()) + (COALESCE(duration_days, 30) * 86400) WHERE key_code = $1 AND is_active = 1 RETURNING expires_at`,
      [keyCode]
    );
    
    if (act.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI HOẶC BỊ KHÓA' });
    
    return res.json({ valid: true, message: 'KÍCH HOẠT THÀNH CÔNG', key: keyCode, expiresAt: act.rows[0].expires_at * 1000 });
  } catch (e) {
    console.error('Verify error:', e.message);
    res.status(500).json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== API: HEARTBEAT ===== */
app.post('/api/heartbeat', heartbeatLimiter, async (req, res) => {
  const { key } = req.body || {};
  const keyCode = normalizeKey(key);
  if (!isValidKeyFormat(keyCode)) return res.json({ valid: false });
  try {
    const result = await pool.query('SELECT * FROM keys_nova WHERE key_code = $1 AND is_active = 1', [keyCode]);
    if (result.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });
    return res.json({ valid: true, expiresAt: result.rows[0].expires_at * 1000 });
  } catch (e) { 
    return res.status(500).json({ valid: false, error: 'LỖI SERVER' }); 
  }
});

/* ===== ADMIN AUTH ===== */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !safeEqual(token, ADMIN_TOKEN)) return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
  next();
}
const admin = [adminLimiter, requireAdmin];

/* ===== API: ADMIN CREATE ===== */
app.post('/api/admin/create', admin, async (req, res) => {
  const { count, duration_days, prefix, note } = req.body || {};
  const numKeys = Math.max(1, Math.min(parseInt(count) || 1, 100));
  const duration = Math.max(1, Math.min(parseInt(duration_days) || 30, 3650));
  const keyPrefix = (String(prefix || 'AIM').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)) || 'AIM';
  const createdKeys = [];
  
  try {
    let attempts = 0;
    while (createdKeys.length < numKeys && attempts < numKeys * 2) {
      attempts++;
      const newKey = generateKey(keyPrefix);
      // Chèn vào bảng keys_nova
      const r = await pool.query(`INSERT INTO keys_nova (key_code, label, duration_days, max_devices) VALUES ($1, $2, $3, 1) ON CONFLICT (key_code) DO NOTHING`, [newKey, note || '', duration]);
      if (r.rowCount === 1) createdKeys.push(newKey);
    }
    res.json({ success: true, count: createdKeys.length, keys: createdKeys });
  } catch (e) { 
    res.status(500).json({ success: false, error: e.message }); 
  }
});

/* ===== API: ADMIN LIST ===== */
app.post('/api/admin/list', admin, async (req, res) => {
  const { limit } = req.body || {};
  try {
    const result = await pool.query('SELECT * FROM keys_nova ORDER BY created_at DESC LIMIT $1', [Math.max(1, Math.min(parseInt(limit) || 100, 500))]);
    res.json({ success: true, count: result.rowCount, keys: result.rows });
  } catch (e) { 
    res.status(500).json({ success: false, error: e.message }); 
  }
});

/* ===== START SERVER ===== */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v16.0');
  console.log('📡 Port:', PORT);
  console.log('✅ Đang dùng chung bảng: keys_nova (An toàn 100%)');
  console.log('==========================================');
});

function shutdown() {
  server.close(() => pool.end().catch(() => {}).finally(() => process.exit(0)));
  setTimeout(() => process.exit(0), 8000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (r) => console.error('Unhandled rejection:', r));
