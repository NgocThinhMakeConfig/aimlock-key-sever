const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'aimlock_default_token_change_me';

app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { valid: false, error: 'QUA NHIEU YEU CAU. THU LAI SAU.' }
});
app.use('/api/', limiter);

const DB_PATH = '/tmp/database.sqlite';
let db = null;
let SQL = null;

async function initDB() {
  SQL = await initSqlJs();
  
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  db.run(`
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
  
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_code TEXT,
      action TEXT,
      device_id TEXT,
      ip TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  saveDB();
  console.log('Database initialized');
}

function saveDB() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch(e) {
    console.error('Save DB error:', e);
  }
}

function queryOne(sql, params) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params || []);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  } catch(e) {
    console.error('Query error:', e);
    return null;
  }
}

function queryAll(sql, params) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params || []);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
  } catch(e) {
    console.error('Query error:', e);
    return [];
  }
}

function execute(sql, params) {
  try {
    db.run(sql, params || []);
    saveDB();
    return true;
  } catch(e) {
    console.error('Execute error:', e);
    return false;
  }
}

function generateKey(prefix) {
  prefix = prefix || 'AIM';
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
    execute('INSERT INTO logs (key_code, action, device_id, ip) VALUES (?, ?, ?, ?)',
      [keyCode, action, deviceId || null, ip || null]);
  } catch(e) { console.error('Log error:', e); }
}

app.get('/', function(req, res) {
  res.json({
    name: 'AIMLOCK KEY SERVER',
    version: '1.0.0',
    status: 'online',
    time: new Date().toISOString()
  });
});

app.post('/api/verify', function(req, res) {
  const key = req.body.key;
  const deviceId = req.body.deviceId;
  const ip = req.ip || 'unknown';

  if (!key || typeof key !== 'string') {
    return res.json({ valid: false, error: 'KEY KHONG HOP LE' });
  }

  const keyCode = key.trim().toUpperCase();

  try {
    const record = queryOne('SELECT * FROM keys WHERE key_code = ?', [keyCode]);

    if (!record) {
      logAction(keyCode, 'INVALID_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY KHONG TON TAI' });
    }

    if (record.status === 'banned') {
      logAction(keyCode, 'BANNED_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY DA BI KHOA' });
    }

    if (record.status === 'expired') {
      logAction(keyCode, 'EXPIRED_KEY', deviceId, ip);
      return res.json({ valid: false, error: 'KEY DA HET HAN' });
    }

    if (record.expires_at) {
      const expiresAt = new Date(record.expires_at);
      if (expiresAt < new Date()) {
        execute('UPDATE keys SET status = ? WHERE key_code = ?', ['expired', keyCode]);
        logAction(keyCode, 'KEY_EXPIRED', deviceId, ip);
        return res.json({ valid: false, error: 'KEY DA HET HAN' });
      }
    }

    if (record.status === 'unused' || !record.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (record.duration_days || 30));

      execute('UPDATE keys SET status = ?, activated_at = CURRENT_TIMESTAMP, expires_at = ?, used_by = ?, device_id = ? WHERE key_code = ?',
        ['active', expiresAt.toISOString(), deviceId || null, deviceId || null, keyCode]);

      logAction(keyCode, 'KEY_ACTIVATED', deviceId, ip);

      return res.json({
        valid: true,
        message: 'KICH HOAT THANH CONG',
        key: keyCode,
        expiresAt: expiresAt.toISOString(),
        durationDays: record.duration_days
      });
    }

    if (record.device_id && deviceId && record.device_id !== deviceId) {
      logAction(keyCode, 'DEVICE_MISMATCH', deviceId, ip);
      return res.json({ valid: false, error: 'KEY DA DUNG TREN THIET BI KHAC' });
    }

    logAction(keyCode, 'VERIFY_OK', deviceId, ip);
    return res.json({
      valid: true,
      message: 'XAC THUC THANH CONG',
      key: keyCode,
      expiresAt: record.expires_at
    });

  } catch(e) {
    console.error('Verify error:', e);
    res.json({ valid: false, error: 'LOI SERVER' });
  }
});

app.post('/api/heartbeat', function(req, res) {
  const key = req.body.key;
  const deviceId = req.body.deviceId;
  if (!key) return res.json({ valid: false });

  try {
    const record = queryOne('SELECT * FROM keys WHERE key_code = ?', [key.toUpperCase()]);
    if (!record || record.status !== 'active') return res.json({ valid: false });

    if (record.expires_at && new Date(record.expires_at) < new Date()) {
      execute('UPDATE keys SET status = ? WHERE key_code = ?', ['expired', record.key_code]);
      return res.json({ valid: false, error: 'KEY DA HET HAN' });
    }

    if (record.device_id && deviceId && record.device_id !== deviceId) {
      return res.json({ valid: false, error: 'DEVICE KHONG KHOP' });
    }

    return res.json({ valid: true, expiresAt: record.expires_at });
  } catch(e) {
    return res.json({ valid: false });
  }
});

app.post('/api/admin/create', function(req, res) {
  const token = req.body.token;
  const count = req.body.count;
  const duration_days = req.body.duration_days;
  const prefix = req.body.prefix;
  const note = req.body.note;

  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  const numKeys = Math.min(parseInt(count) || 1, 100);
  const duration = parseInt(duration_days) || 30;
  const keyPrefix = prefix || 'AIM';
  const createdKeys = [];

  try {
    for (let i = 0; i < numKeys; i++) {
      let newKey = generateKey(keyPrefix);
      let attempts = 0;
      while (queryOne('SELECT id FROM keys WHERE key_code = ?', [newKey]) && attempts < 10) {
        newKey = generateKey(keyPrefix);
        attempts++;
      }
      execute('INSERT INTO keys (key_code, duration_days, note) VALUES (?, ?, ?)',
        [newKey, duration, note || null]);
      createdKeys.push(newKey);
    }

    res.json({ success: true, count: createdKeys.length, duration_days: duration, keys: createdKeys });
  } catch(e) {
    console.error('Create error:', e);
    res.status(500).json({ error: 'LOI TAO KEY' });
  }
});

app.post('/api/admin/list', function(req, res) {
  const token = req.body.token;
  const status = req.body.status;
  const limit = req.body.limit;

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

    const rows = queryAll(query, params);
    res.json({ success: true, count: rows.length, keys: rows });
  } catch(e) {
    res.status(500).json({ error: 'LOI' });
  }
});

app.post('/api/admin/set-status', function(req, res) {
  const token = req.body.token;
  const key = req.body.key;
  const status = req.body.status;

  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  if (['active', 'banned', 'expired', 'unused'].indexOf(status) === -1) {
    return res.json({ error: 'STATUS KHONG HOP LE' });
  }

  try {
    execute('UPDATE keys SET status = ? WHERE key_code = ?', [status, key.toUpperCase()]);
    res.json({ success: true, key: key.toUpperCase(), status: status });
  } catch(e) {
    res.status(500).json({ error: 'LOI' });
  }
});

app.post('/api/admin/delete', function(req, res) {
  const token = req.body.token;
  const key = req.body.key;

  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    execute('DELETE FROM keys WHERE key_code = ?', [key.toUpperCase()]);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'LOI' });
  }
});

app.post('/api/admin/reset-device', function(req, res) {
  const token = req.body.token;
  const key = req.body.key;

  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    execute('UPDATE keys SET device_id = NULL WHERE key_code = ?', [key.toUpperCase()]);
    res.json({ success: true, message: 'DA RESET THIET BI' });
  } catch(e) {
    res.status(500).json({ error: 'LOI' });
  }
});

app.post('/api/admin/stats', function(req, res) {
  const token = req.body.token;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'UNAUTHORIZED' });

  try {
    const total = queryOne('SELECT COUNT(*) as c FROM keys');
    const active = queryOne("SELECT COUNT(*) as c FROM keys WHERE status = 'active'");
    const banned = queryOne("SELECT COUNT(*) as c FROM keys WHERE status = 'banned'");
    const expired = queryOne("SELECT COUNT(*) as c FROM keys WHERE status = 'expired'");
    const unused = queryOne("SELECT COUNT(*) as c FROM keys WHERE status = 'unused'");

    res.json({
      success: true,
      stats: {
        total: total ? total.c : 0,
        active: active ? active.c : 0,
        banned: banned ? banned.c : 0,
        expired: expired ? expired.c : 0,
        unused: unused ? unused.c : 0
      }
    });
  } catch(e) {
    res.status(500).json({ error: 'LOI' });
  }
});

initDB().then(function() {
  app.listen(PORT, function() {
    console.log('AIMLOCK KEY SERVER running on port ' + PORT);
  });
}).catch(function(e) {
  console.error('Init DB failed:', e);
  process.exit(1);
});
