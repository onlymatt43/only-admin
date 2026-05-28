// Shared helper for admin endpoints — NOT exposed as a Vercel API route (underscore prefix)
// Uses Turso HTTP API directly (avoids @libsql/client migration bug)

let tableReady = false;

function getAllowedOrigins() {
  return String(process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
}

function parseJsonSafe(value, fallback) {
  try {
    return JSON.parse(value || JSON.stringify(fallback));
  } catch (_err) {
    return fallback;
  }
}

// Direct Turso HTTP API — bypasses @libsql/client entirely
async function tursoQuery(sql, args = []) {
  const url = process.env.TURSO_DB_URL.replace('libsql://', 'https://');
  const stmtArgs = args.map(a => {
    if (a === null || a === undefined) return { type: 'null' };
    if (typeof a === 'number') return Number.isInteger(a) ? { type: 'integer', value: String(a) } : { type: 'float', value: a };
    return { type: 'text', value: String(a) };
  });

  const resp = await fetch(`${url}/v2/pipeline`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.TURSO_DB_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      requests: [
        { type: 'execute', stmt: { sql, args: stmtArgs } },
        { type: 'close' }
      ]
    })
  });

  if (!resp.ok) throw new Error(`Turso API ${resp.status}: ${await resp.text()}`);
  const data = await resp.json();

  if (data.results[0].type === 'error') {
    throw new Error(data.results[0].error.message);
  }

  const result = data.results[0].response.result;
  const cols = result.cols.map(c => c.name);
  const rows = result.rows.map(row => {
    const obj = {};
    row.forEach((val, i) => {
      if (val.type === 'null') obj[cols[i]] = null;
      else if (val.type === 'integer') obj[cols[i]] = parseInt(val.value, 10);
      else if (val.type === 'float') obj[cols[i]] = parseFloat(val.value);
      else obj[cols[i]] = val.value;
    });
    return obj;
  });

  return { rows, columns: cols, rowsAffected: result.affected_row_count };
}

// Wraps tursoQuery to match the db.execute({sql, args}) pattern used in endpoints
function getDb() {
  if (!process.env.TURSO_DB_URL || !process.env.TURSO_DB_TOKEN) {
    throw new Error('TURSO_DB_URL and TURSO_DB_TOKEN are required');
  }
  return {
    execute: (sqlOrObj, args) => {
      if (typeof sqlOrObj === 'object') return tursoQuery(sqlOrObj.sql, sqlOrObj.args || []);
      return tursoQuery(sqlOrObj, args || []);
    }
  };
}

async function ensureTable() {
  if (tableReady) return;
  const db = getDb();

  // Create table with all current columns (no-op if already exists)
  await db.execute(`
    CREATE TABLE IF NOT EXISTS media_items (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL DEFAULT 'video',
      title TEXT NOT NULL DEFAULT '',
      description TEXT DEFAULT '',
      tags TEXT DEFAULT '[]',
      category TEXT DEFAULT '',
      date_filmed TEXT,
      date_uploaded TEXT DEFAULT (datetime('now')),
      is_private INTEGER DEFAULT 0,
      is_locked INTEGER DEFAULT 0,
      status TEXT DEFAULT 'published',
      platforms_published TEXT DEFAULT '[]',
      primary_format TEXT DEFAULT '16x9',
      formats TEXT DEFAULT '{}',
      source_type TEXT DEFAULT 'upload',
      source_url TEXT DEFAULT '',
      cta_label TEXT DEFAULT '',
      pricing_mode TEXT DEFAULT '',
      lifecycle_stage TEXT DEFAULT '',
      quality_level TEXT DEFAULT 'draft',
      sort_order INTEGER DEFAULT 0,
      is_featured INTEGER DEFAULT 0,
      notes TEXT DEFAULT '',
      family_slug TEXT DEFAULT '',
      bunny_library TEXT DEFAULT 'public',
      storage_path TEXT DEFAULT '',
      file_size INTEGER DEFAULT 0,
      duration REAL DEFAULT 0,
      updated_at TEXT DEFAULT (datetime('now')),
      last_synced_at TEXT DEFAULT NULL,
      sync_status TEXT DEFAULT 'ok',
      sync_error TEXT DEFAULT NULL,
      external_updated_at TEXT DEFAULT NULL,
      social_meta TEXT DEFAULT '{}',
      dedup_key TEXT DEFAULT NULL,
      duplicate_of TEXT DEFAULT NULL,
      duplicate_status TEXT DEFAULT NULL,
      destinations TEXT DEFAULT '[]'
    )
  `);

  // Non-destructive migration: add new columns to existing databases.
  // SQLite does not support IF NOT EXISTS on ALTER TABLE, so we catch
  // "duplicate column name" errors and continue.
  const migrations = [
    "ALTER TABLE media_items ADD COLUMN last_synced_at TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN sync_status TEXT DEFAULT 'ok'",
    "ALTER TABLE media_items ADD COLUMN sync_error TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN external_updated_at TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN social_meta TEXT DEFAULT '{}'",
    "ALTER TABLE media_items ADD COLUMN dedup_key TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN duplicate_of TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN duplicate_status TEXT DEFAULT NULL",
    "ALTER TABLE media_items ADD COLUMN family_slug TEXT DEFAULT ''",
    "ALTER TABLE media_items ADD COLUMN cta_label TEXT DEFAULT ''",
    "ALTER TABLE media_items ADD COLUMN pricing_mode TEXT DEFAULT ''",
    "ALTER TABLE media_items ADD COLUMN lifecycle_stage TEXT DEFAULT ''",
    "ALTER TABLE media_items ADD COLUMN quality_level TEXT DEFAULT 'draft'",
    "ALTER TABLE media_items ADD COLUMN sort_order INTEGER DEFAULT 0",
    "ALTER TABLE media_items ADD COLUMN is_featured INTEGER DEFAULT 0",
    "ALTER TABLE media_items ADD COLUMN destinations TEXT DEFAULT '[]'"
  ];
  for (const sql of migrations) {
    try {
      await db.execute(sql);
    } catch (e) {
      if (!e.message.includes('duplicate column')) throw e;
    }
  }

  tableReady = true;
}

function checkAuth(req) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) {
    console.error('[AUTH] ADMIN_TOKEN env var is not set');
    return false;
  }
  const auth = req.headers['authorization'];
  if (!auth) {
    console.error('[AUTH] No Authorization header received');
    return false;
  }
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    console.error('[AUTH] Malformed Authorization header:', auth.substring(0, 20));
    return false;
  }
  const submitted = parts[1].trim();
  const expected = token.trim();
  console.log(`[AUTH] Token lengths: submitted=${submitted.length}, expected=${expected.length}`);
  if (submitted === expected) return true;
  console.error('[AUTH] Token mismatch');
  return false;
}

function corsHeaders(req, res) {
  const allowedOrigins = getAllowedOrigins();
  const origin = String(req?.headers?.origin || '').trim();
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

// Parse a row from DB into a clean JS object
function parseRow(row) {
  return {
    ...row,
    tags: parseJsonSafe(row.tags, []),
    formats: parseJsonSafe(row.formats, {}),
    social_meta: parseJsonSafe(row.social_meta, {}),
    destinations: parseJsonSafe(row.destinations, []),
    is_private: row.is_private === 1 || row.is_private === true,
    is_locked: row.is_locked === 1 || row.is_locked === true,
    is_featured: row.is_featured === 1 || row.is_featured === true,
  };
}

module.exports = { getDb, ensureTable, checkAuth, corsHeaders, parseRow };
