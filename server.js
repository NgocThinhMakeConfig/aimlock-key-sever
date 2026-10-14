/* ============================================================ */
/* AIMLOCK KEY SERVER v3.0 — FINAL STABLE VERSION */
/* Fix tất cả lỗi: CORS, trust proxy, JSON DB, lock device */
/* ============================================================ */
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();

/* ============================================== */
/* ⭐ FIX #1: TRUST PROXY (BẮT BUỘC CHO RENDER) */
/* ============================================== */
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';
const DB_PATH = process.env.NODE_ENV === 'production' ? '/tmp/keys.json' : './keys.json';

/* ============================================== */
/* ⭐ FIX #2: CORS ĐẦY ĐỦ */
/* ============================================== */
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
  credentials: false,
  maxAge: 86400,
  optionsSuccessStatus: 200
}));

/* ============================================== */
/* ⭐ FIX #3: XỬ LÝ OPTIONS NGAY LẬP TỨC */
/* Đặt TRƯỚC mọi middleware khác */
/* ============================================== */
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization');
    res.header('Access-Control-Max-Age', '86400');
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json({ limit: '10kb' }));

/* ============================================== */
/* ⭐ FIX #4: RATE LIMIT — BỎ QUA OPTIONS */
/* ============================================== */
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  skip: (req) => req.method === 'OPTIONS',
  message: { valid: false, error: 'QUÁ NHIỀU YÊU CẦU. THỬ LẠI SAU.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

/* ============================================== */
/* DATABASE (JSON file - không cần compile) */
/* ============================================== */
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const data = fs.readFileSync(DB_PATH, 'utf8');
      return JSON.parse(data);
    }
  } catch(e) {
    console.error('Load DB error:', e.message);
  }
  return { keys: {}, logs: [] };
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  } catch(e) {
    console.error('Save DB error:', e.message);
  }
}

let db = loadDB();

/* ============================================== */
/* HELPERS */
/* ============================================== */
function logAction(keyCode, action, deviceId, ip) {
  try {
    db.logs.push({
      key_code: keyCode,
      action: action,
      device_id: deviceId || null,
      ip: ip || null,
      timestamp: new Date().toISOString()
    });
    if (db.logs.length > 1000) db.logs = db.logs.slice(-500);
    saveDB(db);
  } catch(e) {
    console.error('Log error:', e.message);
  }
}

function getClientIp(req) {
  return req.ip ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.connection?.remoteAddress ||
    'unknown';
}

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
  if (!key || typeof key !== 'string') return false;
  if (key.length < 10 || key.length > 30) return false;
  return /^[A-Z0-9\-]+$/i.test(key);
}

/* ============================================== */
/* HEALTH CHECK */
/* ============================================== */
app.get('/', (req, res) => {
  res.json({
    name: 'AIMLOCK KEY SERVER',
    version: '3.0.0',
    status: 'online',
    time: new Date().toISOString()
  });
});

app.get('/api/ping', (req, res) => {
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/* ============================================== */
/* VERIFY KEY — LOCK DEVICE */
/* ============================================== */
app.post('/api/verify', (req, res) => {
  const { key, deviceId } = req.body;
  const ip = getClientIp(req);

  if (!isValidKeyFormat(key)) {
    return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
  }

  if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 5) {
    return res.json({ valid: false, error: 'THIẾU DEVICE ID' });
  }

  const keyCode = key.trim().toUpperCase();

  try {
    db = loadDB();
    const record = db.keys[keyCode];

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

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      record.status = 'expired';
      saveDB(db);
      logAction(keyCode, 'KEY_EXPIRED', deviceId, ip);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // ⭐ KÍCH HOẠT LẦN ĐẦU
    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));

      record.status = 'active';
      record.activated_at = new Date().toISOString();
      record.expires_at = expiresAt.toISOString();
      record.device_id = deviceId;
      record.device_locked_at = new Date().toISOString();
      record.last_seen = new Date().toISOString();
      saveDB(db);

      logAction(keyCode, 'KEY_ACTIVATED', deviceId, ip);
      console.log('[ACTIVATE]', keyCode, '→', deviceId);

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

    // ⭐ CHECK DEVICE
    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      console.log('[REJECT]', keyCode, 'locked to', record.device_id);

      return res.json({
        valid: false,
        error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC',
        currentDevice: deviceId,
        lockedDevice: record.device_id.substring(0, 8) + '...',
        hint: 'Liên hệ admin để reset thiết bị'
      });
    }

    record.last_seen = new Date().toISOString();
    saveDB(db);
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
/* HEARTBEAT — AUTO LOGOUT KHI HẾT HẠN */
/* ============================================== */
app.post('/api/heartbeat', (req, res) => {
  const { key, deviceId } = req.body;
  const ip = getClientIp(req);

  if (!key || !deviceId) {
    return res.json({ valid: false, error: 'THIẾU DỮ LIỆU' });
  }

  try {
    db = loadDB();
    const keyCode = key.toUpperCase();
    const record = db.keys[keyCode];

    if (!record) {
      return res.json({ valid: false, error: 'KEY KHÔNG TỒN TẠI' });
    }

    if (record.status === 'banned') {
      return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    }

    if (record.status !== 'active') {
      return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });
    }

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      record.status = 'expired';
      saveDB(db);
      logAction(keyCode, 'HEARTBEAT_EXPIRED', deviceId, ip);
      return res.json({
        valid: false,
        error: 'KEY ĐÃ HẾT HẠN',
        expiresAt: record.expires_at
      });
    }

    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'HEARTBEAT_DEVICE_MISMATCH', deviceId, ip);
      return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });
    }

    record.last_seen = new Date().toISOString();
    saveDB(db);

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
/* ADMIN ENDPOINTS */
/* ============================================== */
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

  try {
    db = loadDB();
    const createdKeys = [];

    for (let i = 0; i < numKeys; i++) {
      let newKey = generateKey(keyPrefix);
      let attempts = 0;
      while (db.keys[newKey] && attempts < 10) {
        newKey = generateKey(keyPrefix);
        attempts++;
      }

      db.keys[newKey] = {
        key_code: newKey,
        status: 'unused',
        duration_days: duration,
        created_at: new Date().toISOString(),
        activated_at: null,
        expires_at: null,
        device_id: null,
        device_locked_at: null,
        last_seen: null,
        note: note || null
      };

      createdKeys.push(newKey);
    }

    saveDB(db);
    res.json({
      success: true,
      count: createdKeys.length,
      duration_days: duration,
      keys: createdKeys
    });
  } catch(e) {
    console.error('Create error:', e);
    res.status(500).json({ error: 'LỖI TẠO KEY' });
  }
});

// List keys
app.post('/api/admin/list', requireAdmin, (req, res) => {
  const { status, limit } = req.body;

  try {
    db = loadDB();
    let keys = Object.values(db.keys);

    if (status && status !== 'all') {
      keys = keys.filter(k => k.status === status);
    }

    keys.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    keys = keys.slice(0, Math.min(parseInt(limit) || 100, 500));

    res.json({ success: true, count: keys.length, keys: keys });
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
    db = loadDB();
    const k = key.toUpperCase();
    if (!db.keys[k]) return res.json({ success: false, error: 'KEY NOT FOUND' });

    db.keys[k].status = status;
    saveDB(db);
    res.json({ success: true, key: k, status: status });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Delete key
app.post('/api/admin/delete', requireAdmin, (req, res) => {
  const { key } = req.body;

  try {
    db = loadDB();
    const k = key.toUpperCase();
    if (db.keys[k]) {
      delete db.keys[k];
      saveDB(db);
      return res.json({ success: true });
    }
    res.json({ success: false, error: 'KEY NOT FOUND' });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Reset device
app.post('/api/admin/reset-device', requireAdmin, (req, res) => {
  const { key } = req.body;

  try {
    db = loadDB();
    const k = key.toUpperCase();
    if (!db.keys[k]) return res.json({ success: false, error: 'KEY NOT FOUND' });

    db.keys[k].device_id = null;
    db.keys[k].device_locked_at = null;
    db.keys[k].last_seen = null;
    saveDB(db);

    logAction(k, 'ADMIN_RESET_DEVICE', null, getClientIp(req));
    console.log('[ADMIN] Reset device for', k);

    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Extend key
app.post('/api/admin/extend', requireAdmin, (req, res) => {
  const { key, days } = req.body;
  const extendDays = parseInt(days) || 30;

  try {
    db = loadDB();
    const k = key.toUpperCase();
    if (!db.keys[k]) return res.status(404).json({ error: 'KEY NOT FOUND' });

    const record = db.keys[k];
    let newExpiry;

    if (record.expires_at && new Date(record.expires_at) > new Date()) {
      newExpiry = new Date(record.expires_at);
      newExpiry.setDate(newExpiry.getDate() + extendDays);
    } else {
      newExpiry = new Date();
      newExpiry.setDate(newExpiry.getDate() + extendDays);
    }

    record.expires_at = newExpiry.toISOString();
    record.status = 'active';
    saveDB(db);

    logAction(k, 'ADMIN_EXTEND', null, getClientIp(req));

    res.json({
      success: true,
      message: 'Đã gia hạn ' + extendDays + ' ngày',
      newExpiry: newExpiry.toISOString()
    });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Stats
app.post('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    db = loadDB();
    const keys = Object.values(db.keys);
    const fiveMinAgo = new Date(Date.now() - 5 * 60000).toISOString();

    res.json({
      success: true,
      stats: {
        total: keys.length,
        active: keys.filter(k => k.status === 'active').length,
        banned: keys.filter(k => k.status === 'banned').length,
        expired: keys.filter(k => k.status === 'expired').length,
        unused: keys.filter(k => k.status === 'unused').length,
        online: keys.filter(k => k.status === 'active' && k.last_seen > fiveMinAgo).length
      }
    });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Logs
app.post('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    db = loadDB();
    const logs = db.logs.slice(-200).reverse();
    res.json({ success: true, logs: logs });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

/* ============================================== */
/* 404 HANDLER */
/* ============================================== */
app.use((req, res) => {
  res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' });
});

/* ============================================== */
/* ERROR HANDLER */
/* ============================================== */
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'LỖI SERVER' });
});

/* ============================================== */
/* START */
/* ============================================== */
app.listen(PORT, () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v3.0');
  console.log('📡 Port: ' + PORT);
  console.log('💾 DB: ' + DB_PATH);
  console.log('🔐 Admin token: ' + ADMIN_TOKEN.substring(0, 8) + '...');
  console.log('✅ Trust proxy: enabled');
  console.log('✅ CORS: enabled for all origins');
  console.log('==========================================');
});

process.on('SIGTERM', () => {
  console.log('Đang tắt server...');
  process.exit(0);
});
