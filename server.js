/* ============================================================ */
/* AIMLOCK KEY SERVER v4.0 - POSTGRESQL FINAL                   */
/* Lưu trữ vĩnh viễn, không bao giờ mất key                     */
/* ============================================================ */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';

// Kết nối Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Bắt buộc đối với Render PostgreSQL
});

// Tự động tạo bảng khi server khởi động
async function initDB() {
  try {
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
    console.log('✅ Database đã sẵn sàng và kết nối thành công!');
  } catch (err) {
    console.error('❌ Lỗi khởi tạo DB:', err.message);
  }
}
initDB();

/* ⭐ CORS FIX */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

app.use(express.json({ limit: '10kb' }));

/* ===== HELPERS ===== */
function generateKey(prefix = 'AIM') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let parts = [];
  for (let p = 0; p < 4; p++) {
    let part = '';
    for (let i = 0; i < 4; i++) part += chars.charAt(Math.floor(Math.random() * chars.length));
    parts.push(part);
  }
  return prefix + '-' + parts.join('-');
}

function isValidKeyFormat(key) {
  if (!key || typeof key !== 'string') return false;
  if (key.length < 10 || key.length > 40) return false;
  return /^[A-Z0-9\-]+$/i.test(key) && /[A-Z0-9]/i.test(key);
}

/* ===== HEALTH CHECK ===== */
app.get('/', (req, res) => {
  res.json({ name: 'AIMLOCK KEY SERVER', version: '4.0.0', status: 'online', time: new Date().toISOString() });
});

/* ===== VERIFY KEY ===== */
app.post('/api/verify', async (req, res) => {
  const { key, deviceId } = req.body || {};
  if (!isValidKeyFormat(key)) return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
  if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 5) return res.json({ valid: false, error: 'THIẾU DEVICE ID' });

  const keyCode = key.trim().toUpperCase();

  try {
    const result = await pool.query('SELECT * FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });

    const record = result.rows[0];

    if (record.status === 'banned') return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      await pool.query('UPDATE keys SET status = $1 WHERE key_code = $2', ['expired', keyCode]);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // Kích hoạt lần đầu
    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));

      await pool.query(
        `UPDATE keys SET status = 'active', activated_at = NOW(), expires_at = $1, device_id = $2, last_seen = NOW() WHERE key_code = $3`,
        [expiresAt.toISOString(), deviceId, keyCode]
      );
      return res.json({ valid: true, message: 'KÍCH HOẠT THÀNH CÔNG', key: keyCode, expiresAt: expiresAt.toISOString() });
    }

    if (record.device_id && record.device_id !== deviceId) {
      return res.json({ valid: false, error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC' });
    }

    await pool.query('UPDATE keys SET last_seen = NOW() WHERE key_code = $1', [keyCode]);
    return res.json({ valid: true, message: 'XÁC THỰC THÀNH CÔNG', key: keyCode, expiresAt: record.expires_at });

  } catch (e) {
    console.error(e);
    res.status(500).json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== HEARTBEAT ===== */
app.post('/api/heartbeat', async (req, res) => {
  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.json({ valid: false });

  try {
    const keyCode = key.toUpperCase();
    const result = await pool.query('SELECT * FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });

    const record = result.rows[0];
    if (record.status !== 'active') return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      await pool.query('UPDATE keys SET status = $1 WHERE key_code = $2', ['expired', keyCode]);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }
    if (record.device_id && record.device_id !== deviceId) return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });

    await pool.query('UPDATE keys SET last_seen = NOW() WHERE key_code = $1', [keyCode]);
    return res.json({ valid: true, expiresAt: record.expires_at });

  } catch (e) {
    return res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== ADMIN AUTH ===== */
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || (req.body && req.body.token);
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });
  next();
}

/* ===== ADMIN: TẠO KEY ===== */
app.post('/api/admin/create', requireAdmin, async (req, res) => {
  const { count, duration_days, prefix, note } = req.body || {};
  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = parseInt(duration_days) || 30;
  const keyPrefix = prefix || 'AIM';
  const createdKeys = [];

  try {
    for (let i = 0; i < numKeys; i++) {
      let newKey = generateKey(keyPrefix);
      let exists = true;
      while (exists) {
        const check = await pool.query('SELECT 1 FROM keys WHERE key_code = $1', [newKey]);
        if (check.rowCount === 0) exists = false;
        else newKey = generateKey(keyPrefix);
      }
      await pool.query(
        `INSERT INTO keys (key_code, duration_days, note) VALUES ($1, $2, $3)`,
        [newKey, duration, note || null]
      );
      createdKeys.push(newKey);
    }
    res.json({ success: true, count: createdKeys.length, keys: createdKeys });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'LỖI TẠO KEY' });
  }
});

/* ===== ADMIN: DANH SÁCH KEY ===== */
app.post('/api/admin/list', requireAdmin, async (req, res) => {
  const { status, limit } = req.body || {};
  try {
    let query = 'SELECT * FROM keys';
    let params = [];
    if (status && status !== 'all') {
      query += ' WHERE status = $1';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
    params.push(Math.min(parseInt(limit) || 100, 500));

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rowCount, keys: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'LỖI' });
  }
});

/* ===== ADMIN: THỐNG KÊ ===== */
app.post('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'active') as active,
        COUNT(*) FILTER (WHERE status = 'banned') as banned,
        COUNT(*) FILTER (WHERE status = 'expired') as expired,
        COUNT(*) FILTER (WHERE status = 'unused') as unused
      FROM keys
    `);
    const stats = result.rows[0];
    Object.keys(stats).forEach(k => stats[k] = parseInt(stats[k]));
    res.json({ success: true, stats });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'LỖI' });
  }
});

/* ===== ADMIN: ĐỔI STATUS ===== */
app.post('/api/admin/set-status', requireAdmin, async (req, res) => {
  const { key, status } = req.body || {};
  const validStatus = ['unused', 'active', 'expired', 'banned'];
  if (!validStatus.includes(status)) return res.status(400).json({ success: false, error: 'STATUS KHÔNG HỢP LỆ' });
  
  try {
    const keyCode = String(key || '').toUpperCase();
    const result = await pool.query('UPDATE keys SET status = $1 WHERE key_code = $2', [status, keyCode]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== ADMIN: XÓA KEY ===== */
app.post('/api/admin/delete', requireAdmin, async (req, res) => {
  const { key } = req.body || {};
  try {
    const keyCode = String(key || '').toUpperCase();
    const result = await pool.query('DELETE FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== ADMIN: RESET DEVICE ===== */
app.post('/api/admin/reset-device', requireAdmin, async (req, res) => {
  const { key } = req.body || {};
  try {
    const keyCode = String(key || '').toUpperCase();
    const result = await pool.query('UPDATE keys SET device_id = NULL, last_seen = NULL WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== ADMIN: GIA HẠN ===== */
app.post('/api/admin/extend', requireAdmin, async (req, res) => {
  const { key, days } = req.body || {};
  const extendDays = Math.max(1, Math.min(parseInt(days) || 30, 3650));
  
  try {
    const keyCode = String(key || '').toUpperCase();
    const result = await pool.query('SELECT * FROM keys WHERE key_code = $1', [keyCode]);
    if (result.rowCount === 0) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    
    const record = result.rows[0];
    const now = new Date();
    let base = (record.expires_at && new Date(record.expires_at) > now) ? new Date(record.expires_at) : now;
    base.setDate(base.getDate() + extendDays);
    
    await pool.query(
      `UPDATE keys SET expires_at = $1, status = 'active', activated_at = COALESCE(activated_at, NOW()) WHERE key_code = $2`,
      [base.toISOString(), keyCode]
    );
    res.json({ success: true, newExpiry: base.toISOString() });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== 404 ===== */
app.use((req, res) => res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' }));

/* ===== START ===== */
app.listen(PORT, () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v4.0 (PostgreSQL)');
  console.log('📡 Port:', PORT);
  console.log('✅ Đã kết nối Database tự động!');
  console.log('==========================================');
});

process.on('SIGTERM', () => process.exit(0));
