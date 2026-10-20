/* ============================================================ */
/* AIMLOCK KEY SERVER v3.6 — FIXED                              */
/* Fix: race condition, rate-limit, validate, graceful shutdown */
/* ============================================================ */
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_secret_2026';

if (!ADMIN_TOKEN) {
  console.error('❌ FATAL: ADMIN_TOKEN chưa được set trong env!');
  console.error('   Chạy: ADMIN_TOKEN=your_secret node server.js');
  process.exit(1);
}
if (ADMIN_TOKEN === 'aimlock_secret_2026') {
  console.warn('⚠️  CẢNH BÁO: ADMIN_TOKEN đang dùng giá trị mặc định, hãy đổi!');
}

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'keys.json');

/* ⭐ CORS */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

/* ===== DATABASE (JSON) — GHI TUẦN TỰ ===== */
let db = { keys: {}, logs: [] };
let writeLock = Promise.resolve();     // Hàng đợi ghi tuần tự
let dirty = false;                     // Cờ cần flush

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed.keys) parsed.keys = {};
      if (!Array.isArray(parsed.logs)) parsed.logs = [];
      return parsed;
    }
  } catch (e) {
    console.error('Load DB error:', e.message);
  }
  return { keys: {}, logs: [] };
}

// Ghi an toàn + tuần tự (không race condition)
function saveDB(data) {
  dirty = true;
  writeLock = writeLock.then(() => {
    try {
      const tempPath = DB_PATH + '.tmp';
      fs.writeFileSync(tempPath, JSON.stringify(data, null, 2));
      fs.renameSync(tempPath, DB_PATH);
      dirty = false;
    } catch (e) {
      console.error('Save DB error:', e.message);
    }
  }).catch(e => console.error('WriteLock error:', e.message));
  return writeLock;
}

db = loadDB();

/* ===== HELPERS ===== */
function generateKey(prefix = 'AIM') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const parts = [];
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
  if (key.length < 10 || key.length > 40) return false;
  // Phải có ít nhất 1 chữ/số, không chỉ toàn dấu -
  if (!/[A-Z0-9]/i.test(key)) return false;
  return /^[A-Z0-9\-]+$/i.test(key);
}

function normalizeIp(ip) {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
}

function logAction(keyCode, action, deviceId, ip) {
  db.logs.push({
    key_code: keyCode, action: action,
    device_id: deviceId || null, ip: normalizeIp(ip),
    timestamp: new Date().toISOString()
  });
  // Giữ 2000 log gần nhất (dễ debug hơn)
  if (db.logs.length > 2000) db.logs = db.logs.slice(-1000);
  saveDB(db);
}

/* ===== RATE LIMIT đơn giản (in-memory) ===== */
const rateBuckets = new Map();     // ip -> {count, resetAt}
const RATE_LIMIT = 30;             // 30 request
const RATE_WINDOW = 60 * 1000;     // / phút

function rateLimit(req, res, next) {
  const ip = normalizeIp(req.ip);
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + RATE_WINDOW };
    rateBuckets.set(ip, b);
  }
  b.count++;
  if (b.count > RATE_LIMIT) {
    return res.status(429).json({ valid: false, error: 'QUÁ NHIỀU YÊU CẦU, THỬ LẠI SAU' });
  }
  next();
}

// Dọn bucket định kỳ
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of rateBuckets) if (now > b.resetAt) rateBuckets.delete(ip);
}, 60 * 1000).unref();

/* ===== HEALTH ===== */
app.get('/', (req, res) => {
  res.json({ name: 'AIMLOCK KEY SERVER', version: '3.6.0', status: 'online', time: new Date().toISOString() });
});

/* ===== VERIFY ===== */
app.post('/api/verify', rateLimit, (req, res) => {
  const { key, deviceId } = req.body || {};
  const ip = req.ip || 'unknown';

  if (!isValidKeyFormat(key)) return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
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

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      if (record.status !== 'expired') {
        record.status = 'expired';
        saveDB(db);
      }
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
      record.last_seen = new Date().toISOString();
      saveDB(db);

      logAction(keyCode, 'KEY_ACTIVATED', deviceId, ip);
      console.log('[ACTIVATE]', keyCode, '→', deviceId);

      return res.json({
        valid: true, message: 'KÍCH HOẠT THÀNH CÔNG', key: keyCode,
        expiresAt: expiresAt.toISOString(), deviceId, isFirstActivation: true
      });
    }

    // Check device
    if (record.device_id && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      return res.json({ valid: false, error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC' });
    }

    record.last_seen = new Date().toISOString();
    saveDB(db);
    logAction(keyCode, 'VERIFY_OK', deviceId, ip);

    return res.json({ valid: true, message: 'XÁC THỰC THÀNH CÔNG', key: keyCode, expiresAt: record.expires_at });

  } catch (e) {
    console.error('Verify error:', e);
    res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== HEARTBEAT ===== */
app.post('/api/heartbeat', rateLimit, (req, res) => {
  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) return res.json({ valid: false });

  try {
    db = loadDB();
    const keyCode = key.toUpperCase();
    const record = db.keys[keyCode];

    if (!record || record.status !== 'active') return res.json({ valid: false, error: 'KEY KHÔNG HOẠT ĐỘNG' });

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      record.status = 'expired';
      saveDB(db);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }
    if (record.device_id && record.device_id !== deviceId) return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });

    record.last_seen = new Date().toISOString();
    saveDB(db);
    return res.json({ valid: true, expiresAt: record.expires_at });

  } catch (e) {
    return res.json({ valid: false, error: 'LỖI SERVER' });
  }
});

/* ===== ADMIN ===== */
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || (req.body && req.body.token);
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });
  next();
}

const VALID_STATUS = ['unused', 'active', 'expired', 'banned'];

// Tạo key
app.post('/api/admin/create', requireAdmin, (req, res) => {
  const { count, duration_days, prefix, note } = req.body || {};
  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = Math.max(1, Math.min(parseInt(duration_days) || 30, 3650));
  const keyPrefix = (typeof prefix === 'string' && /^[A-Z]{2,10}$/i.test(prefix)) ? prefix.toUpperCase() : 'AIM';

  try {
    db = loadDB();
    const createdKeys = [];

    for (let i = 0; i < numKeys; i++) {
      let newKey;
      let attempts = 0;
      do {
        newKey = generateKey(keyPrefix);
        if (++attempts > 50) throw new Error('Không tạo được key unique (đã thử 50 lần)');
      } while (db.keys[newKey]);

      db.keys[newKey] = {
        key_code: newKey, status: 'unused', duration_days: duration,
        created_at: new Date().toISOString(), activated_at: null, expires_at: null,
        device_id: null, last_seen: null, note: typeof note === 'string' ? note.slice(0, 200) : null
      };
      createdKeys.push(newKey);
    }
    saveDB(db);
    res.json({ success: true, count: createdKeys.length, keys: createdKeys });
  } catch (e) {
    console.error('Create error:', e.message);
    res.status(500).json({ error: 'LỖI TẠO KEY', detail: e.message });
  }
});

// List
app.post('/api/admin/list', requireAdmin, (req, res) => {
  const { status, limit } = req.body || {};
  try {
    db = loadDB();
    let keys = Object.values(db.keys);
    if (status && status !== 'all' && VALID_STATUS.includes(status)) {
      keys = keys.filter(k => k.status === status);
    }
    keys.sort((a, b) => {
      const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
      const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
      return tb - ta;
    });
    keys = keys.slice(0, Math.min(parseInt(limit) || 100, 500));
    res.json({ success: true, count: keys.length, keys });
  } catch (e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

// Set status
app.post('/api/admin/set-status', requireAdmin, (req, res) => {
  const { key, status } = req.body || {};
  if (!VALID_STATUS.includes(status)) {
    return res.status(400).json({ success: false, error: 'STATUS KHÔNG HỢP LỆ' });
  }
  try {
    db = loadDB();
    const k = String(key || '').toUpperCase();
    if (!db.keys[k]) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    db.keys[k].status = status;
    saveDB(db);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

// Delete
app.post('/api/admin/delete', requireAdmin, (req, res) => {
  const { key } = req.body || {};
  try {
    db = loadDB();
    const k = String(key || '').toUpperCase();
    if (db.keys[k]) { delete db.keys[k]; saveDB(db); return res.json({ success: true }); }
    res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

// Reset device
app.post('/api/admin/reset-device', requireAdmin, (req, res) => {
  const { key } = req.body || {};
  try {
    db = loadDB();
    const k = String(key || '').toUpperCase();
    if (!db.keys[k]) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    db.keys[k].device_id = null;
    db.keys[k].last_seen = null;
    saveDB(db);
    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

// Extend
app.post('/api/admin/extend', requireAdmin, (req, res) => {
  const { key, days } = req.body || {};
  const extendDays = Math.max(1, Math.min(parseInt(days) || 30, 3650));
  try {
    db = loadDB();
    const k = String(key || '').toUpperCase();
    if (!db.keys[k]) return res.json({ success: false, error: 'KEY KHÔNG TỒN TẠI' });
    const record = db.keys[k];

    const now = new Date();
    let base = (record.expires_at && new Date(record.expires_at) > now)
      ? new Date(record.expires_at)
      : now;
    const newExpiry = new Date(base);
    newExpiry.setDate(newExpiry.getDate() + extendDays);

    record.expires_at = newExpiry.toISOString();
    record.status = 'active';
    if (!record.activated_at) record.activated_at = now.toISOString();
    saveDB(db);
    res.json({ success: true, newExpiry: newExpiry.toISOString() });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
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
        online: keys.filter(k => k.status === 'active' && k.last_seen && k.last_seen > fiveMinAgo).length
      }
    });
  } catch (e) { res.status(500).json({ error: 'LỖI' }); }
});

/* ===== 404 ===== */
app.use((req, res) => {
  res.status(404).json({ error: 'ENDPOINT KHÔNG TỒN TẠI' });
});

/* ===== GRACEFUL SHUTDOWN ===== */
function shutdown(signal) {
  console.log(`\n[${signal}] Đang flush DB và tắt...`);
  writeLock.finally(() => {
    if (dirty) {
      try {
        fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
        console.log('✅ Đã flush DB lần cuối.');
      } catch (e) { console.error('Flush error:', e.message); }
    }
    process.exit(0);
  });
  // Cưỡng bức exit sau 5s nếu treo
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

/* ===== START ===== */
const server = app.listen(PORT, () => {
  console.log('==========================================');
  console.log('🚀 AIMLOCK KEY SERVER v3.6');
  console.log('📡 Port:', PORT);
  console.log('💾 DB:', DB_PATH);
  console.log('✅ Auto-clean: TẮT');
  console.log('✅ Safe Save: BẬT (write lock + atomic rename)');
  console.log('✅ Rate limit: 30 req/phút/IP');
  console.log('✅ Validate status: BẬT');
  console.log('==========================================');
});

// Đảm bảo server không treo test
module.exports = { app, server };
