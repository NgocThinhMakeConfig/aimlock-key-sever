/* ============================================================ */
/* AIMLOCK KEY SERVER v4.1 — POSTGRESQL (Bảng riêng aimlock_keys)*/
/* ============================================================ */
const express = require('express');
const { Pool } = require('pg'); 

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';

// Kết nối tới Database có sẵn
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Tự động tạo bảng aimlock_keys nếu chưa có
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS aimlock_keys (
        id SERIAL PRIMARY KEY,
        key_code TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'unused',
        duration_days INTEGER DEFAULT 30,
        created_at TIMESTAMP DEFAULT NOW(),
        activated_at TIMESTAMP,
        expires_at TIMESTAMP,
        device_id TEXT,
        last_seen TIMESTAMP,
        note TEXT
      );
    `);
    console.log('✅ Database đã sẵn sàng (Bảng aimlock_keys)');
  } catch (err) {
    console.error('❌ Lỗi kết nối DB:', err.message);
  }
}
initDB();

/* ⭐ CORS FIX */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', '*');
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

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.body.token;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });
  next();
}

/* ===== API VERIFY ===== */
app.post('/api/verify', async (req, res) => {
  const { key, deviceId } = req.body;
  if (!key || !deviceId) return res.json({ valid: false, error: 'THIẾU THÔNG TIN' });

  const keyCode = key.trim().toUpperCase();

  try {
    const { rows } = await pool.query('SELECT * FROM aimlock_keys WHERE key_code = $1', [keyCode]);
    const record = rows[0];

    if (!record) return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });
    if (record.status === 'banned') return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      await pool.query('UPDATE aimlock_keys SET status = $1 WHERE id = $2', ['expired', record.id]);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // Kích hoạt lần đầu
    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));
      
      await pool.query(`
        UPDATE aimlock_keys SET status = 'active', activated_at = NOW(), expires_at = $1, device_id = $2, last_seen = NOW() WHERE id = $3
      `, [expiresAt, deviceId, record.id]);

      return res.json({ valid: true, message: 'KÍCH HOẠT THÀNH CÔNG', key: keyCode, expiresAt: expiresAt.toISOString(), deviceId });
    }

    // Check Device
    if (record.device_id && record.device_id !== deviceId) {
      return res.json({ valid: false, error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC' });
    }

    await pool.query('UPDATE aimlock_keys SET last_seen = NOW() WHERE id = $1', [record.id]);
    return res.json({ valid: true, message: 'XÁC THỰC THÀNH CÔNG', key: keyCode, expiresAt: record.expires_at });

  } catch (e) {
    console.error(e);
    res.status(500).json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== API ADMIN ===== */
app.post('/api/admin/create', requireAdmin, async (req, res) => {
  const { count, duration_days, prefix, note } = req.body;
  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = parseInt(duration_days) || 30;
  const keyPrefix = prefix || 'AIM';

  try {
    const createdKeys = [];
    for (let i = 0; i < numKeys; i++) {
      let newKey = generateKey(keyPrefix);
      await pool.query(`
        INSERT INTO aimlock_keys (key_code, duration_days, note) VALUES ($1, $2, $3)
      `, [newKey, duration, note || null]);
      createdKeys.push(newKey);
    }
    res.json({ success: true, count: createdKeys.length, keys: createdKeys });
  } catch (e) {
    res.status(500).json({ error: 'LỖI TẠO KEY' });
  }
});

app.post('/api/admin/list', requireAdmin, async (req, res) => {
  const { status, limit } = req.body;
  try {
    let query = 'SELECT * FROM aimlock_keys';
    let params = [];
    if (status && status !== 'all') {
      query += ' WHERE status = $1';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
    params.push(Math.min(parseInt(limit) || 100, 500));

    const { rows } = await pool.query(query, params);
    res.json({ success: true, count: rows.length, keys: rows });
  } catch (e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.post('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'active') as active,
        COUNT(*) FILTER (WHERE status = 'unused') as unused,
        COUNT(*) FILTER (WHERE status = 'expired') as expired,
        COUNT(*) FILTER (WHERE status = 'banned') as banned
      FROM aimlock_keys
    `);
    res.json({ success: true, stats: rows[0] });
  } catch (e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.post('/api/admin/set-status', requireAdmin, async (req, res) => {
  const { key, status } = req.body;
  try {
    await pool.query('UPDATE aimlock_keys SET status = $1 WHERE key_code = $2', [status, key.toUpperCase()]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

app.post('/api/admin/delete', requireAdmin, async (req, res) => {
  const { key } = req.body;
  try {
    await pool.query('DELETE FROM aimlock_keys WHERE key_code = $1', [key.toUpperCase()]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

app.post('/api/admin/reset-device', requireAdmin, async (req, res) => {
  const { key } = req.body;
  try {
    await pool.query('UPDATE aimlock_keys SET device_id = NULL, last_seen = NULL WHERE key_code = $1', [key.toUpperCase()]);
    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== START ===== */
app.listen(PORT, () => {
  console.log('🚀 AIMLOCK KEY SERVER v4.1 (PostgreSQL)');
  console.log('📡 Port:', PORT);
});
