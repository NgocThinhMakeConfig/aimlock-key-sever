const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_default_token_change_me';

app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { valid: false, error: 'QUÁ NHIỀU YÊU CẦU. THỬ LẠI SAU.' }
});
app.use('/api/', limiter);

const DB_PATH = process.env.NODE_ENV === 'production' ? '/tmp/database.sqlite' : './database.sqlite';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

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
    max_devices INTEGER DEFAULT 1,
    note TEXT
  )
`);

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

function logAction(keyCode, action, deviceId, ip) {
  try {
    db.prepare('INSERT INTO logs (key_code, action, device_id, ip) VALUES (?, ?, ?, ?)')
      .run(keyCode, action, deviceId || null, ip || null);
  } catch(e) { console.error('Log error:', e); }
}

app.get('/', (req, res) => {
  res.json({
    name: 'AIMLOCK KEY SERVER',
    version: '1.0.0',
    status: 'online',
    time: new Date().toISOString()
  });
});

app.post('/api/verify', (req, res) => {
  const { key, deviceId } = req.body;
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';

  if (!key || typeof key !== 'string') {
    return res.json({ valid: false, error: 'KEY KHÔNG HỢP LỆ' });
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

    if (record.expires_at) {
      const expiresAt = new Date(record.expires_at);
      if (expiresAt < new Date()) {
        db.prepare('UPDATE keys SET status = ? WHERE key_code = ?').run('expired', keyCode);
        logAction(keyCode, 'KEY_EXPIRED', deviceId, ip);
        return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
      }
    }

    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));

      db.prepare(`
        UPDATE keys SET status = 'active', activated_at = CURRENT_TIMESTAMP,
          expires_at = ?, used_by = ?, device_id = ? WHERE key_code = ?
      `).run(expiresAt.toISOString(), deviceId || null, deviceId || null, keyCode);

      logAction(keyCode, 'KEY_ACTIVATED', deviceId, ip);

      return res.json({
        valid: true,
        message: 'KÍCH HOẠT THÀNH CÔNG',
        key: keyCode,
        expiresAt: expiresAt.toISOString(),
        durationDays: record.duration_days
      });
    }

    if (record.device_id && deviceId && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      return res.json({ valid: false, error: 'KEY ĐÃ DÙNG TRÊN THIẾT BỊ KHÁC' });
    }

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

app.post('/api/heartbeat', (req, res) => {
  const { key, deviceId } = req.body;
  if (!key) return res.json({ valid: false });

  try {
    const record = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key.toUpperCase());
    if (!record || record.status !== 'active') return res.json({ valid: false });

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      db.prepare('UPDATE keys SET status = ? WHERE key_code = ?').run('expired', record.key_code);
      return res.json({ valid: false, error: 'KEY ĐÃ HẾT HẠN' });
    }

    if (record.device_id && deviceId && record.device_id !== deviceId) {
      return res.json({ valid: false, error: 'DEVICE KHÔNG KHỚP' });
    }

    return res.json({ valid: true, expiresAt: record.expires_at });
  } catch(e) {
    return res.json({ valid: false });
  }
});

app.post('/api/admin/create', (req, res) => {
  const { token, count, duration_days, prefix, note } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

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

app.post('/api/admin/list', (req, res) => {
  const { token, status, limit } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

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

app.post('/api/admin/set-status', (req, res) => {
  const { token, key, status } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  if (!['active', 'banned', 'expired', 'unused'].includes(status)) {
    return res.json({ error: 'STATUS KHÔNG HỢP LỆ' });
  }

  try {
    const result = db.prepare('UPDATE keys SET status = ? WHERE key_code = ?').run(status, key.toUpperCase());
    res.json({ success: result.changes > 0, key: key.toUpperCase(), status });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.post('/api/admin/delete', (req, res) => {
  const { token, key } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    db.prepare('DELETE FROM keys WHERE key_code = ?').run(key.toUpperCase());
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.post('/api/admin/reset-device', (req, res) => {
  const { token, key } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    db.prepare('UPDATE keys SET device_id = NULL WHERE key_code = ?').run(key.toUpperCase());
    res.json({ success: true, message: 'ĐÃ RESET THIẾT BỊ' });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.post('/api/admin/stats', (req, res) => {
  const { token } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    const total = db.prepare('SELECT COUNT(*) as c FROM keys').get().c;
    const active = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'active'").get().c;
    const banned = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'banned'").get().c;
    const expired = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'expired'").get().c;
    const unused = db.prepare("SELECT COUNT(*) as c FROM keys WHERE status = 'unused'").get().c;

    res.json({ success: true, stats: { total, active, banned, expired, unused } });
  } catch(e) {
    res.status(500).json({ error: 'LỖI' });
  }
});

app.listen(PORT, () => {
  console.log(`AIMLOCK KEY SERVER running on port ${PORT}`);
});
