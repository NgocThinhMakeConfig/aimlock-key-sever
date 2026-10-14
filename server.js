/* ============================================================ */
/* AIMLOCK KEY SERVER v2.0 — FULL FEATURES */
/* ============================================================ */
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';

/* ============================================== */
/* ===== CORS — FIX CHO MOBILE ===== */
/* ============================================== */
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
  credentials: false,
  maxAge: 86400  // Cache preflight 24h
}));

// ⭐ QUAN TRỌNG: Xử lý OPTIONS preflight cho mọi route
app.options('*', cors());

app.use(express.json({ limit: '10kb' }));

/* ============================================== */
/* ===== RATE LIMIT ===== */
/* ============================================== */
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,  // ⭐ Tăng từ 30 → 120
  message: { valid: false, error: 'QUÁ NHIỀU YÊU CẦU. THỬ LẠI SAU.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

/* ============================================== */
/* ===== DATABASE ===== */
/* ============================================== */
const DB_PATH = process.env.NODE_ENV === 'production' 
  ? '/tmp/database.sqlite' 
  : './database.sqlite';

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Bảng keys
db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'unused',
    duration_days INTEGER DEFAULT 30,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    activated_at DATETIME,
    expires_at DATETIME,
    used_by TEXT,
    device_id TEXT,
    device_locked_at DATETIME,
    last_seen DATETIME,
    max_devices INTEGER DEFAULT 1,
    note TEXT
  )
`);

// Bảng logs
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT,
    action TEXT,
    device_id TEXT,
    ip TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

/* ============================================== */
/* ===== HELPERS ===== */
/* ============================================== */
function generateKey(prefix = 'AIM') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let parts = [];
  for (let p = 0; p < 4; p++) {
    let part = '';
    for (let i = 0; i < 4; i++) {
      part += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    parts.push(part);
  }
  return prefix + '-' + parts.join('-');
}

function isValidKeyFormat(key) {
  // Format: XXX-XXXX-XXXX-XXXX-XXXX (dài 22-24 ký tự)
  if (!key || typeof key !== 'string') return false;
  if (key.length < 10 || key.length > 30) return false;
  return /^[A-Z0-9\-]+$/i.test(key);
}

function logAction(keyCode, action, deviceId, ip) {
  try {
    db.prepare('INSERT INTO logs (key_code, action, device_id, ip) VALUES (?, ?, ?, ?)')
      .run(keyCode, action, deviceId || null, ip || null);
  } catch(e) { 
    console.error('Log error:', e.message); 
  }
}

function getClientIp(req) {
  return req.ip || 
    req.headers['x-forwarded-for']?.split(',')[0] || 
    req.connection?.remoteAddress || 
    'unknown';
}

/* ============================================== */
/* ===== HEALTH CHECK ===== */
/* ============================================== */
app.get('/', (req, res) => {
  res.json({
    name: 'AIMLOCK KEY SERVER',
    version: '2.0.0',
    status: 'online',
    time: new Date().toISOString()
  });
});

// ⭐ Endpoint /api/ping — để UptimeRobot wake server
app.get('/api/ping', (req, res) => {
  res.json({ 
    status: 'ok', 
    time: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/* ============================================== */
/* ===== VERIFY KEY — LOCK DEVICE ===== */
/* ============================================== */
app.post('/api/verify', (req, res) => {
  const { key, deviceId } = req.body;
  const ip = getClientIp(req);

  // ⭐ Validate input
  if (!isValidKeyFormat(key)) {
    return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
  }

  if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 5) {
    return res.json({ valid: false, error: 'THIẾU DEVICE ID' });
  }

  const keyCode = key.trim().toUpperCase();

  try {
    const record = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(keyCode);

    if (!record) {
      logAction(keyCode, 'INVALID_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });
    }

    if (record.status === 'banned') {
      logAction(keyCode, 'BANNED_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    }

    if (record.status === 'expired') {
      logAction(keyCode, 'EXPIRED_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // Kiểm tra hết hạn tự động
    if (record.expires_at) {
      const expiresAt = new Date(record.expires_at);
      if (expiresAt < new Date()) {
        db.prepare('UPDATE keys SET status = ? WHERE key_code = ?').run('expired', keyCode);
        logAction(keyCode, 'KEY_EXPIRED', deviceId, ip);
        return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
      }
    }

    /* ===== KÍCH HOẠT LẦN ĐẦU ===== */
    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));

      db.prepare(`
        UPDATE keys SET 
          status = 'active', 
          activated_at = CURRENT_TIMESTAMP,
          expires_at = ?, 
          used_by = ?, 
          device_id = ?, 
          device_locked_at = CURRENT_TIMESTAMP,
          last_seen = CURRENT_TIMESTAMP
        WHERE key_code = ?
      `).run(expiresAt.toISOString(), deviceId, deviceId, keyCode);

      logAction(keyCode, 'KEY_ACTIVATED', deviceId, ip);
      console.log(`[ACTIVATE] ${keyCode} → ${deviceId}`);

      return res.json({
        valid: true,
        message: 'KÍCH HOẠT THÀNH CÔNG',
        key: keyCode,
        expiresAt: expiresAt.toISOString(),
        durationDays: record.duration_days,
        deviceId: deviceId,
        isFirstActivation: true
      });
    }

    /* ===== ⭐ CHECK DEVICE — NGHIÊM NGẶT ===== */
    // Nếu key đã lock device mà device khác → TỪ CHỐI
    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      console.log(`[REJECT] ${keyCode} locked to ${record.device_id}, got ${deviceId}`);
      
      return res.json({ 
        valid: false, 
        error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC',
        currentDevice: deviceId,
        lockedDevice: record.device_id.substring(0, 8) + '...',
        hint: 'Liên hệ admin để reset thiết bị'
      });
    }

    // ⭐ Update last_seen
    db.prepare('UPDATE keys SET last_seen = CURRENT_TIMESTAMP WHERE key_code = ?').run(keyCode);

    logAction(keyCode, 'VERIFY_OK', deviceId, ip);
    return res.json({
      valid: true,
      message: 'XÁC THỰC THÀNH CÔNG',
      key: keyCode,
      expiresAt: record.expires_at,
      deviceId: record.device_id
    });

  } catch(e) {
    console.error('Verify error:', e);
    res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ============================================== */
/* ===== HEARTBEAT — KIỂM TRA ĐỊNH KỲ ===== */
/* ============================================== */
app.post('/api/heartbeat', (req, res) => {
  const { key, deviceId } = req.body;
  const ip = getClientIp(req);

  if (!key || !deviceId) {
    return res.json({ valid: false, error: 'THIẾU DỮ LIỆU' });
  }

  try {
    const keyCode = key.toUpperCase();
    const record = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(keyCode);

    if (!record) {
      return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });
    }

    if (record.status === 'banned') {
      return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    }

    if (record.status !== 'active') {
      return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });
    }

    // ⭐ Check hết hạn — TỰ ĐỘNG UPDATE DB
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      db.prepare('UPDATE keys SET status = ? WHERE key_code = ?').run('expired', keyCode);
      logAction(keyCode, 'HEARTBEAT_EXPIRED', deviceId, ip);
      console.log(`[EXPIRED] ${keyCode} — auto marked expired`);
      return res.json({ 
        valid: false, 
        error: 'KEY ĐÃ HẾT HẠN',
        expiresAt: record.expires_at
      });
    }

    // ⭐ Check device
    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'HEARTBEAT_DEVICE_MISMATCH', deviceId, ip);
      return res.json({ 
        valid: false, 
        error: 'DEVICE KHÔNG KHỚP'
      });
    }

    // Update last_seen
    db.prepare('UPDATE keys SET last_seen = CURRENT_TIMESTAMP WHERE key_code = ?').run(keyCode);

    // Tính thời gian còn lại
    const timeLeftMs = new Date(record.expires_at) - new Date();
    const timeLeftSeconds = Math.floor(timeLeftMs / 1000);
    const timeLeftDays = Math.floor(timeLeftSeconds / 86400);

    return res.json({ 
      valid: true, 
      expiresAt: record.expires_at,
      timeLeftSeconds: timeLeftSeconds,
      timeLeftDays: timeLeftDays
    });

  } catch(e) {
    console.error('Heartbeat error:', e);
    return res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ============================================== */
/* ===== ADMIN ENDPOINTS ===== */
/* ============================================== */

// Middleware check admin token
function requireAdmin(req, res, next) {
  const { token } = req.body;
  if (token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'UNAUTHORIZED' });
  }
  next();
}

// Tạo key
app.post('/api/admin/create', requireAdmin, (req, res) => {
  const { count, duration_days, prefix, note } = req.body;
  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = parseInt(duration_days) || 30;
  const keyPrefix = prefix || 'AIM';
  const createdKeys = [];

  try {
    const insert = db.prepare('INSERT INTO keys (key_code, duration_days, note) VALUES (?, ?, ?)');

    for (let i = 0; i < numKeys; i++) {
      let newKey = generateKey(keyPrefix);
      let attempts = 0;
      while (db.prepare('SELECT id FROM keys WHERE key_code = ?').get(newKey) && attempts < 10) {
        newKey = generateKey(keyPrefix);
        attempts++;
      }
      insert.run(newKey, duration, note || null);
      createdKeys.push(newKey);
    }

    res.json({ success: true, count: createdKeys.length, duration_days: duration, keys: createdKeys });
  } catch(e) {
    console.error('Create error:', e);
    res.status(500).json({ error: 'LỖI TẠO KEY' });
  }
});

// List keys
app.post('/api/admin/list', requireAdmin, (req, res) => {
  const { status, limit } = req.body;

  try {
    let query = 'SELECT * FROM keys';
    let params = [];
    if (status && status !== 'all') {
      query += ' WHERE status = ?';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(Math.min(parseInt(limit) || 100, 500));

    const rows = db.prepare(query).all(...params);
    res.json({ success: true, count: rows.length, keys: rows });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Set status
app.post('/api/admin/set-status', requireAdmin, (req, res) => {
  const { key, status } = req.body;

  if (!['active', 'banned', 'expired', 'unused'].includes(status)) {
    return res.json({ error: 'STATUS KHÔNG HỢP LỆ' });
  }

  try {
    const result = db.prepare('UPDATE keys SET status = ? WHERE key_code = ?')
      .run(status, key.toUpperCase());
    res.json({ success: result.changes > 0, key: key.toUpperCase(), status });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Delete key
app.post('/api/admin/delete', requireAdmin, (req, res) => {
  const { key } = req.body;

  try {
    const result = db.prepare('DELETE FROM keys WHERE key_code = ?').run(key.toUpperCase());
    res.json({ success: result.changes > 0 });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// ⭐ Reset device — cho user đổi máy
app.post('/api/admin/reset-device', requireAdmin, (req, res) => {
  const { key } = req.body;

  try {
    const result = db.prepare(`
      UPDATE keys SET 
        device_id = NULL, 
        device_locked_at = NULL,
        last_seen = NULL
      WHERE key_code = ?
    `).run(key.toUpperCase());

    if (result.changes > 0) {
      logAction(key.toUpperCase(), 'ADMIN_RESET_DEVICE', null, getClientIp(req));
      console.log(`[ADMIN] Reset device for ${key.toUpperCase()}`);
    }

    res.json({ 
      success: result.changes > 0, 
      message: result.changes > 0 ? 'ĐÃ RESET THIẾT BỊ' : 'KHÔNG TÌM THẤY KEY'
    });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// ⭐ Reset expiry — gia hạn key
app.post('/api/admin/extend', requireAdmin, (req, res) => {
  const { key, days } = req.body;
  const extendDays = parseInt(days) || 30;

  try {
    const record = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key.toUpperCase());
    if (!record) return res.status(404).json({ error: 'KEY NOT FOUND' });

    let newExpiry;
    if (record.expires_at && new Date(record.expires_at) > new Date()) {
      // Còn hạn → cộng thêm
      newExpiry = new Date(record.expires_at);
      newExpiry.setDate(newExpiry.getDate() + extendDays);
    } else {
      // Hết hạn → bắt đầu từ hôm nay
      newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + extendDays);
    }

    db.prepare(`
      UPDATE keys SET 
        expires_at = ?, 
        status = 'active'
      WHERE key_code = ?
    `).run(newExpiry.toISOString(), key.toUpperCase());

    logAction(key.toUpperCase(), 'ADMIN_EXTEND', null, getClientIp(req));

    res.json({ 
      success: true, 
      message: `Đã gia hạn ${extendDays} ngày`,
      newExpiry: newExpiry.toISOString()
    });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Stats
app.post('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const total = db.prepare('SELECT COUNT(*) as c FROM keys').get().c;
    const active = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'active'").get().c;
    const banned = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'banned'").get().c;
    const expired = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'expired'").get().c;
    const unused = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'unused'").get().c;

    // Đếm key active trong 5 phút gần đây (đang online)
    const online = db.prepare(`
      SELECT COUNT(*) as c FROM keys 
      WHERE status = 'active' 
      AND last_seen > datetime('now', '-5 minutes')
    `).get().c;

    res.json({ 
      success: true, 
      stats: { total, active, banned, expired, unused, online }
    });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

/* ============================================== */
/* ===== 404 HANDLER ===== */
/* ============================================== */
app.use((req, res) => {
  res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' });
});

/* ============================================== */
/* ===== START ===== */
/* ============================================== */
app.listen(PORT, () => {
  console.log('==========================================');
  console.log(`🚀 AIMLOCK KEY SERVER v2.0`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`💾 DB: ${DB_PATH}`);
  console.log(`🔐 Admin token: ${ADMIN_TOKEN.substring(0, 8)}...`);
  console.log('==========================================');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Đang tắt server...');
  db.close();
  process.exit(0);
});
