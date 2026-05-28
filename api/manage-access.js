const crypto = require('crypto');

// Initialisation Turso DB (lazy loading)
let db = null;
let dbInitialized = false;

async function getDb() {
  if (db && dbInitialized) return db;

  try {
    if (!db) {
      const { createClient } = require('@libsql/client/web');
      if (process.env.TURSO_DB_URL && process.env.TURSO_DB_TOKEN) {
        const url = process.env.TURSO_DB_URL.replace('libsql://', 'https://');
        db = createClient({
          url: url,
          authToken: process.env.TURSO_DB_TOKEN,
        });
      }
    }

    if (db && !dbInitialized) {
      // Test connection and create table if needed
      await db.execute('SELECT 1');
      await initDatabase();
      dbInitialized = true;
    }

    return db;
  } catch (error) {
    console.warn("Turso DB error:", error.message);
    return null; // Fallback to in-memory
  }
}

// Génère un secret TOTP aléatoire en Base32
function generateTOTPSecret() {
  const bytes = crypto.randomBytes(20);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}

function getAllowedOrigins() {
  const raw = String(process.env.ALLOWED_ORIGINS || '').trim();
  if (!raw) return [];
  return raw.split(',').map(v => v.trim()).filter(Boolean);
}

// Initialise la DB et crée la table si elle n'existe pas
async function initDatabase() {
  const db = await getDb();
  if (!db) return;

  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS access_codes (
        id INTEGER PRIMARY KEY,
        secret TEXT NOT NULL,
        claimed BOOLEAN DEFAULT FALSE,
        claimed_at DATETIME,
        claimed_ip TEXT,
        label TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Vérifie si on a déjà des codes, sinon en crée 10
    const result = await db.execute("SELECT COUNT(*) as count FROM access_codes");
    if (result.rows[0].count === 0) {
      // Insère les 10 codes initiaux
      for (let i = 1; i <= 10; i++) {
        const secret = generateTOTPSecret();
        const label = `Admin Access ${i}`;
        await db.execute(
          "INSERT INTO access_codes (id, secret, label) VALUES (?, ?, ?)",
          [i, secret, label]
        );
      }
      console.log("Initialized 10 access codes in database");
    }
  } catch (error) {
    console.error("Database initialization error:", error);
  }
}

// Récupère tous les codes depuis la DB
async function getAccessCodes() {
  const db = await getDb();
  if (!db) {
    // Fallback en mémoire si DB pas disponible
    return generateAccessCodesFallback();
  }

  try {
    const result = await db.execute("SELECT * FROM access_codes ORDER BY id");
    return result.rows.map(row => ({
      id: row.id,
      secret: row.secret,
      claimed: row.claimed === 1,
      claimedAt: row.claimed_at,
      label: row.label
    }));
  } catch (error) {
    console.error("Error fetching access codes:", error);
    return generateAccessCodesFallback();
  }
}

// Fallback en mémoire (comme avant)
function generateAccessCodesFallback() {
  const codes = [];
  for (let i = 1; i <= 10; i++) {
    codes.push({
      id: i,
      secret: generateTOTPSecret(),
      claimed: false,
      claimedAt: null,
      label: `Admin Access ${i}`
    });
  }
  return codes;
}

module.exports = async (req, res) => {
  // CORS — restrict to known frontend origins
  const _orig = req.headers.origin || '';
  const allowedOrigins = getAllowedOrigins();
  if (allowedOrigins.includes(_orig)) {
    res.setHeader('Access-Control-Allow-Origin', _orig);
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    if (req.method === 'GET') {
      // Admin-only: requires Bearer token (set ADMIN_TOKEN env var)
      const adminToken = process.env.ADMIN_TOKEN;
      const auth = req.headers['authorization'] || '';
      if (!adminToken || auth !== `Bearer ${adminToken}`) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      // Retourne la liste des codes avec leur statut
      const accessCodes = await getAccessCodes();
      const publicCodes = accessCodes.map(code => ({
        id: code.id,
        claimed: code.claimed,
        qrUrl: code.claimed ? null : `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/${encodeURIComponent(code.label)}?secret=${code.secret}&issuer=AdminConsole`
      }));
      return res.status(200).json(publicCodes);
    }

    if (req.method === 'POST') {
      // Claim un accès
      const { codeId } = req.body;
      if (!codeId || codeId < 1 || codeId > 10) {
        return res.status(400).json({ error: 'Invalid code ID' });
      }

      const db = await getDb();
      if (!db) {
        return res.status(500).json({ error: 'Database not available' });
      }

      // Vérifie si le code existe et n'est pas déjà claimé
      const checkResult = await db.execute(
        "SELECT * FROM access_codes WHERE id = ?",
        [codeId]
      );

      if (checkResult.rows.length === 0) {
        return res.status(404).json({ error: 'Code not found' });
      }

      const code = checkResult.rows[0];
      if (code.claimed === 1) {
        return res.status(409).json({ error: 'Code already claimed' });
      }

      // Claim the code
      const claimedAt = new Date().toISOString();
      const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                      req.headers['x-real-ip'] || 
                      req.connection.remoteAddress || 
                      req.socket.remoteAddress || 
                      'unknown';
      
      await db.execute(
        "UPDATE access_codes SET claimed = 1, claimed_at = ?, claimed_ip = ? WHERE id = ?",
        [claimedAt, clientIP, codeId]
      );

      return res.status(200).json({
        success: true,
        secret: code.secret,
        label: code.label
      });
    }

    return res.status(405).json({ error: 'Method not allowed' });

  } catch (error) {
    console.error('Access API Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};