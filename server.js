/* ============================================================ */
/* AIMLOCK KEY SERVER v2.1 — CORS FIX + JSON DB */
/* ============================================================ */
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();


app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';
const DB_PATH = process.env.NODE_ENV === 'production' ? '/tmp/keys.json' : './keys.json';

/* ===== CORS — FIX TRIỆT ĐỂ ===== */
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
  credentials: false,
  maxAge: 86400,
  optionsSuccessStatus: 200
}));

// ⭐ Xử lý OPTIONS TRƯỚC rate limit
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

/* ===== RATE LIMIT — BỎ QUA OPTIONS ===== */
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  skip: (req) => req.method === 'OPTIONS',
  message: { valid: false, error: 'QUÁ NHIỀU YÊU CẦU' }
});
app.use('/api/', limiter);

/* ===== DATABASE (JSON) ===== */
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch(e) {}
  return { keys: {}, logs: [] };
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  } catch(e) { console.error('Save error:', e.message); }
}

let db = loadDB();

/* ===== HELPERS ===== */
function logAction(keyCode, action, deviceId, ip) {
  db.logs.push({
    key_code: keyCode, action: action,
    device_id: deviceId || null, ip: ip || null,
    timestamp: new Date().toISOString()
  });
  if (db.logs.length > 1000) db.logs = db.logs.slice(-500);
  saveDB(db);
}

function getClientIp(req) {
  return req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0] || 'unknown';
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

/* ===== HEALTH CHECK ===== */
app.get('/', (req, res) => {
  res.json({
    name: 'AIMLOCK KEY SERVER',
    version: '2.1.0',
    status: 'online',
    time: new Date().toISOString()
  });
});

app.get('/api/ping', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), uptime: process.uptime() });
});

/* ===== VERIFY ===== */
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
      return res.json({ valid: false, error: 'KEY ĐÃ BỊ KHÓA' });
    }
    if (record.status === 'expired') {
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      record.status = 'expired';
      saveDB(db);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    // Kích hoạt lần đầu
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
      return res.json({
        valid: true,
        message: 'KÍCH HOẠT THÀNH CÔNG',
        key: keyCode,
        expiresAt: expiresAt.toISOString(),
        isFirstActivation: true
      });
    }

    // Check device
    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      return res.json({
        valid: false,
        error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC'
      });
    }

    record.last_seen = new Date().toISOString();
    saveDB(db);
    logAction(keyCode, 'VERIFY_OK', deviceId, ip);

    return res.json({
      valid: true,
      message: 'XÁC THỰC THÀNH CÔNG',
      key: keyCode,
      expiresAt: record.expires_at
    });

  } catch(e) {
    console.error('Verify error:', e);
    res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== HEARTBEAT ===== */
app.post('/api/heartbeat', (req, res) => {
  const { key, deviceId } = req.body;
  if (!key || !deviceId) return res.json({ valid: false });

  try {
    db = loadDB();
    const record = db.keys[key.toUpperCase()];

    if (!record || record.status !== 'active') {
      return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });
    }
    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      record.status = 'expired';
      saveDB(db);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }
    if (record.device_id && record.device_id !== deviceId) {
      return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });
    }

    record.last_seen = new Date().toISOString();
    saveDB(db);
    return res.json({ valid: true, expiresAt: record.expires_at });

  } catch(e) {
    return res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== ADMIN ===== */
function requireAdmin(req, res, next) {
  if (req.body.token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });
  next();
}

app.post('/api/admin/create', requireAdmin, (req, res) => {
  const { count, duration_days, prefix, note } = req.body;
  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = parseInt(duration_days) || 30;
  const keyPrefix = prefix || 'AIM';

  db = loadDB();
  const createdKeys = [];
  for (let i = 0; i < numKeys; i++) {
    let newKey = generateKey(keyPrefix);
    while (db.keys[newKey]) newKey = generateKey(keyPrefix);
    
    db.keys[newKey] = {
      key_code: newKey,
      status: 'unused',
      duration_days: duration,
      created_at: new Date().toISOString(),
      activated_at: null,
      expires_at: null,
      device_id: null,
      last_seen: null,
      note: note || null
    };
    createdKeys.push(newKey);
  }
  saveDB(db);
  res.json({ success: true, count: createdKeys.length, keys: createdKeys });
});

app.post('/api/admin/list', requireAdmin, (req, res) => {
  const { status, limit } = req.body;
  db = loadDB();
  let keys = Object.values(db.keys);
  if (status && status !== 'all') keys = keys.filter(k => k.status === status);
  keys.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  keys = keys.slice(0, Math.min(parseInt(limit) || 100, 500));
  res.json({ success: true, count: keys.length, keys });
});

app.post('/api/admin/set-status', requireAdmin, (req, res) => {
  const { key, status } = req.body;
  db = loadDB();
  const k = key.toUpperCase();
  if (!db.keys[k]) return res.json({ success: false });
  db.keys[k].status = status;
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/admin/delete', requireAdmin, (req, res) => {
  const { key } = req.body;
  db = loadDB();
  const k = key.toUpperCase();
  if (db.keys[k]) { delete db.keys[k]; saveDB(db); return res.json({ success: true }); }
  res.json({ success: false });
});

app.post('/api/admin/reset-device', requireAdmin, (req, res) => {
  const { key } = req.body;
  db = loadDB();
  const k = key.toUpperCase();
  if (!db.keys[k]) return res.json({ success: false });
  db.keys[k].device_id = null;
  db.keys[k].device_locked_at = null;
  db.keys[k].last_seen = null;
  saveDB(db);
  res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
});

app.post('/api/admin/extend', requireAdmin, (req, res) => {
  const { key, days } = req.body;
  const extendDays = parseInt(days) || 30;
  db = loadDB();
  const k = key.toUpperCase();
  if (!db.keys[k]) return res.json({ success: false });

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
  res.json({ success: true, newExpiry: newExpiry.toISOString() });
});

app.post('/api/admin/stats', requireAdmin, (req, res) => {
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
});

/* ===== 404 ===== */
app.use((req, res) => {
  res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' });
});

/* ===== START ===== */
app.listen(PORT, () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v2.1');
  console.log('📡 Port: ' + PORT);
  console.log('💾 DB: ' + DB_PATH);
  console.log('==========================================');
});
