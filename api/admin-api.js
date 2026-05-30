const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { getDb, ensureTable, checkAuth, corsHeaders, parseRow } = require('./_admin-db');

function normalizePullZone(value, fallback) {
  const raw = String(value || '').trim();
  if (!raw) return fallback;
  if (/^https?:\/\//i.test(raw)) return raw.replace(/\/$/, '');
  return `https://${raw.replace(/^\/+/, '').replace(/\/$/, '')}`;
}

function readEnv(canonicalName, legacyNames = []) {
  const canonicalValue = String(process.env[canonicalName] || '').trim();
  if (canonicalValue) return canonicalValue;

  for (const legacyName of legacyNames) {
    const legacyValue = String(process.env[legacyName] || '').trim();
    if (legacyValue) return legacyValue;
  }

  return '';
}

function resolveEnv(canonicalName, legacyNames = []) {
  const canonicalValue = String(process.env[canonicalName] || '').trim();
  if (canonicalValue) {
    return { value: canonicalValue, source: canonicalName, used_legacy_alias: false };
  }

  for (const legacyName of legacyNames) {
    const legacyValue = String(process.env[legacyName] || '').trim();
    if (legacyValue) {
      return { value: legacyValue, source: legacyName, used_legacy_alias: true };
    }
  }

  return { value: '', source: null, used_legacy_alias: false };
}

const ENV_STRICT_MODE = String(process.env.ENV_STRICT_MODE || '').trim().toLowerCase() === 'true';

function parseJsonBody(req) {
  if (req && req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (_err) { return {}; }
  }
  return {};
}

function inferUploadType(body) {
  const explicit = String(body?.type || '').trim().toLowerCase();
  if (explicit === 'video' || explicit === 'photo') return explicit;

  const fileName = String(body?.fileName || '').trim().toLowerCase();
  const sourceUrl = String(body?.source_url || '').trim().toLowerCase();
  const hasInlineFile = Boolean(body?.file);

  const imageExt = /\.(png|jpe?g|webp|gif|bmp|heic|heif|avif)(\?.*)?$/i;
  const videoExt = /\.(mp4|mov|m4v|webm|mkv|avi|mpeg|mpg)(\?.*)?$/i;

  if (hasInlineFile && imageExt.test(fileName)) return 'photo';
  if (hasInlineFile && videoExt.test(fileName)) return 'video';

  if (sourceUrl) {
    if (imageExt.test(sourceUrl)) return 'photo';
    if (videoExt.test(sourceUrl)) return 'video';
  }

  // No clear signal: default to video (stream upload path).
  return 'video';
}

function inferUploadStatus(body) {
  const explicit = String(body?.status || '').trim().toLowerCase();
  if (explicit === 'draft' || explicit === 'ready' || explicit === 'published') {
    return explicit;
  }

  const hasEditorialInput = Boolean(
    String(body?.category || '').trim()
    || String(body?.description || '').trim()
    || String(body?.family_slug || '').trim()
    || String(body?.family || '').trim()
    || String(body?.date_filmed || '').trim()
    || String(body?.notes || '').trim()
    || String(body?.source_url || '').trim()
    || String(body?.pricing_mode || '').trim()
    || String(body?.lifecycle_stage || '').trim()
    || String(body?.cta_label || '').trim()
    || (Number(body?.sort_order) || 0) !== 0
    || Boolean(body?.is_featured)
    || String(body?.quality_level || '').trim().toLowerCase() !== 'draft'
    || parseArraySafe(body?.tags).length > 0
    || parseArraySafe(body?.route_tags).length > 0
    || parseArraySafe(body?.destinations).length > 0
  );

  return hasEditorialInput ? 'published' : 'draft';
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value) {
  const input = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (input.length % 4)) % 4;
  const padded = input + '='.repeat(padLen);
  return Buffer.from(padded, 'base64');
}

function getSessionSecret() {
  return String(process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_TOKEN || '').trim();
}

function createSessionToken() {
  const secret = getSessionSecret();
  if (!secret) throw new Error('ADMIN_SESSION_SECRET or ADMIN_TOKEN is required to mint sessions');

  const now = Math.floor(Date.now() / 1000);
  const ttl = Math.max(300, Number(process.env.ADMIN_SESSION_TTL_SECONDS || 43200));
  const payload = {
    typ: 'admin-session',
    iat: now,
    exp: now + ttl,
    nonce: crypto.randomBytes(8).toString('hex')
  };

  const payloadRaw = JSON.stringify(payload);
  const payloadEnc = base64UrlEncode(payloadRaw);
  const sig = crypto.createHmac('sha256', secret).update(payloadEnc).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return {
    token: `${payloadEnc}.${sig}`,
    expires_in: ttl,
    expires_at: payload.exp
  };
}

function verifySessionToken(rawToken) {
  const token = String(rawToken || '').trim();
  if (!token || !token.includes('.')) return false;
  const [payloadEnc, sig] = token.split('.');
  if (!payloadEnc || !sig) return false;

  const secret = getSessionSecret();
  if (!secret) return false;

  const expectedSig = crypto.createHmac('sha256', secret).update(payloadEnc).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  const submittedBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (!(submittedBuf.length === expectedBuf.length && crypto.timingSafeEqual(submittedBuf, expectedBuf))) {
    return false;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(payloadEnc).toString('utf8'));
    if (!payload || payload.typ !== 'admin-session') return false;
    const now = Math.floor(Date.now() / 1000);
    return Number(payload.exp || 0) > now;
  } catch (_err) {
    return false;
  }
}

function readBearerToken(req) {
  const auth = String(req?.headers?.authorization || '').trim();
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return '';
  return String(parts[1] || '').trim();
}

function decodeBase32(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(secret || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function totpAt(secretBuffer, stepSeconds, timestampSeconds) {
  const counter = Math.floor(timestampSeconds / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);
  const digest = crypto.createHmac('sha1', secretBuffer).update(counterBuf).digest();
  const offset = digest[digest.length - 1] & 0xf;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

function verifyTotp(code) {
  const secret = String(process.env.ADMIN_TOTP_SECRET || '').trim();
  if (!secret) return { required: false, ok: true };

  const normalizedCode = String(code || '').trim().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalizedCode)) {
    return { required: true, ok: false };
  }

  const stepSeconds = Math.max(15, Number(process.env.ADMIN_TOTP_STEP_SECONDS || 30));
  const windowSize = Math.max(0, Number(process.env.ADMIN_TOTP_WINDOW || 1));
  const now = Math.floor(Date.now() / 1000);
  const secretBuffer = decodeBase32(secret);
  if (!secretBuffer.length) return { required: true, ok: false };

  for (let drift = -windowSize; drift <= windowSize; drift += 1) {
    const candidate = totpAt(secretBuffer, stepSeconds, now + (drift * stepSeconds));
    const submittedBuf = Buffer.from(normalizedCode, 'utf8');
    const expectedBuf = Buffer.from(candidate, 'utf8');
    if (submittedBuf.length === expectedBuf.length && crypto.timingSafeEqual(submittedBuf, expectedBuf)) {
      return { required: true, ok: true };
    }
  }

  return { required: true, ok: false };
}

function isTotpEnabled() {
  return String(process.env.ADMIN_TOTP_SECRET || '').trim().length > 0;
}

function isAuthorizedRequest(req) {
  const bearer = readBearerToken(req);
  if (bearer && verifySessionToken(bearer)) return true;

  // In TOTP mode we only accept short-lived session tokens.
  if (isTotpEnabled()) return false;

  // Legacy mode fallback: direct ADMIN_TOKEN bearer auth.
  return checkAuth(req, { quiet: true });
}

// ─── Bunny Config ───
const PUBLIC = {
  id: readEnv('BUNNY_PUBLIC_LIBRARY_ID', ['BUNNY_LIBRARY_ID']),
  key: readEnv('BUNNY_PUBLIC_LIBRARY_API_KEY', ['BUNNY_ACCESS_KEY']),
  pull: normalizePullZone(readEnv('BUNNY_PUBLIC_PULL_ZONE_URL', ['BUNNY_PULL_ZONE']), '')
};
const PRIVATE = {
  id: readEnv('BUNNY_PRIVATE_LIBRARY_ID', ['BUNNY_PRIVATE_LIBRARY_ID']),
  key: readEnv('BUNNY_PRIVATE_LIBRARY_API_KEY', ['BUNNY_PRIVATE_ACCESS_KEY', 'BUNNY_API_KEY']),
  pull: normalizePullZone(readEnv('BUNNY_PRIVATE_PULL_ZONE_URL', ['BUNNY_PRIVATE_PULL_ZONE', 'BUNNY_PULL_ZONE_HOST']), '')
};
const STORAGE = {
  name: process.env.BUNNY_STORAGE_NAME || '',
  password: readEnv('BUNNY_STORAGE_API_KEY', ['BUNNY_STORAGE_PASSWORD']),
  pullZone: normalizePullZone(readEnv('BUNNY_STORAGE_PULL_ZONE_URL', ['BUNNY_STORAGE_PULL_ZONE']), '')
};

// ─── Helpers ───
function slugify(text) {
  return text.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/\.[^/.]+$/, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 80);
}

function normalizeFamilySlug(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const cleaned = raw
    .replace(/\.[a-z0-9]{2,4}$/i, '')
    .replace(/\((9x16|16x9|1x1)\)/ig, '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const stripped = cleaned
    .replace(/\b(preview-ever|preview|full-movie|short-video|feature|archive)\b\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim();

  return slugify(stripped || cleaned);
}

function normalizeLifecycleStage(value) {
  const raw = String(value || '').trim().toLowerCase();
  return raw;
}

function normalizePricingMode(value) {
  const raw = String(value || '').trim().toLowerCase();
  return raw;
}

function normalizeQualityLevel(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return 'draft';
  if (raw === 'ready' || raw === 'live') return raw;
  return 'draft';
}

function assertResolvedConfig(requiredRows) {
  const missing = [];
  for (const row of requiredRows) {
    const aliases = Array.isArray(row.aliases) ? row.aliases : [];
    if (!readEnv(row.key, aliases)) {
      missing.push(row.key);
    }
  }
  if (missing.length > 0) {
    throw new Error(`Missing required env vars: ${missing.join(', ')}`);
  }
}

function ensureBunnyVideoConfig(library) {
  if (library === 'private') {
    assertResolvedConfig([
      { key: 'BUNNY_PRIVATE_LIBRARY_ID' },
      { key: 'BUNNY_PRIVATE_LIBRARY_API_KEY', aliases: ['BUNNY_PRIVATE_ACCESS_KEY', 'BUNNY_API_KEY'] },
      { key: 'BUNNY_PRIVATE_PULL_ZONE_URL', aliases: ['BUNNY_PRIVATE_PULL_ZONE', 'BUNNY_PULL_ZONE_HOST'] },
    ]);
    return;
  }
  assertResolvedConfig([
    { key: 'BUNNY_PUBLIC_LIBRARY_ID', aliases: ['BUNNY_LIBRARY_ID'] },
    { key: 'BUNNY_PUBLIC_LIBRARY_API_KEY', aliases: ['BUNNY_ACCESS_KEY'] },
    { key: 'BUNNY_PUBLIC_PULL_ZONE_URL', aliases: ['BUNNY_PULL_ZONE'] },
  ]);
}

function ensureBunnyStorageConfig() {
  assertResolvedConfig([
    { key: 'BUNNY_STORAGE_NAME' },
    { key: 'BUNNY_STORAGE_API_KEY', aliases: ['BUNNY_STORAGE_PASSWORD'] },
    { key: 'BUNNY_STORAGE_PULL_ZONE_URL', aliases: ['BUNNY_STORAGE_PULL_ZONE'] },
  ]);
}

const PREVIEW_CATEGORIES = new Set(['preview', 'preview-ever', 'short-video']);
const VALID_LIFECYCLE_STAGES = new Set(['feature', 'preview-ever', 'archive']);
const ROUTE_TAG_PREFIX = 'route:';

function parseArraySafe(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_err) {
    return [];
  }
}

function isRouteTag(tag) {
  return String(tag || '').toLowerCase().startsWith(ROUTE_TAG_PREFIX);
}

function normalizeRouteTag(tag) {
  const raw = String(tag || '').trim().toLowerCase();
  if (!raw) return '';
  if (!raw.startsWith(ROUTE_TAG_PREFIX)) return '';
  return raw.replace(/[^a-z0-9:-]/g, '');
}

function routeTagFromDestination(dest) {
  const raw = String(dest || '').trim().toLowerCase();
  if (!raw) return '';
  return normalizeRouteTag(`${ROUTE_TAG_PREFIX}${raw}`);
}

function destinationFromRouteTag(tag) {
  const norm = normalizeRouteTag(tag);
  if (!norm) return '';
  const route = norm.slice(ROUTE_TAG_PREFIX.length);
  if (route === 'super-videotheque' || route === 'viewer-only') return route;
  if (route === 'catalog') return 'super-videotheque';
  if (route === 'main-site' || route === 'chaud-devant') return 'viewer-only';
  if (route.startsWith('project:')) return route;
  return '';
}

function buildRouteTags({ tags, destinations, route_tags }) {
  const out = new Set();
  for (const t of parseArraySafe(tags)) {
    const norm = normalizeRouteTag(t);
    if (norm) out.add(norm);
  }
  for (const d of parseArraySafe(destinations)) {
    const routeTag = routeTagFromDestination(d);
    if (routeTag) out.add(routeTag);
  }
  for (const rt of parseArraySafe(route_tags)) {
    const norm = normalizeRouteTag(rt);
    if (norm) out.add(norm);
  }
  return [...out];
}

function buildDestinationsFromRouteTags(routeTags) {
  const out = new Set();
  for (const tag of parseArraySafe(routeTags)) {
    const dest = destinationFromRouteTag(tag);
    if (dest) out.add(dest);
  }
  return [...out];
}

function withRouteFields(item) {
  const route_tags = buildRouteTags({ tags: item.tags, destinations: item.destinations });
  const destinations = [...new Set([
    ...parseArraySafe(item.destinations),
    ...buildDestinationsFromRouteTags(route_tags)
  ])];
  const contentTags = parseArraySafe(item.tags).filter(t => !isRouteTag(t));
  return {
    ...item,
    tags: [...new Set([...contentTags, ...route_tags])],
    destinations,
    route_tags,
  };
}

function parseTagBoxRow(row) {
  let payload = {};
  try {
    payload = JSON.parse(row.payload || '{}');
  } catch (_err) {
    payload = {};
  }
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    payload,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
  };
}

function buildValidationWarnings(item) {
  const warnings = [];
  const type = String(item.type || '').toLowerCase();
  const category = String(item.category || '').trim().toLowerCase();
  const sourceUrl = String(item.source_url || '').trim();
  const familySlug = String(item.family_slug || '').trim();
  const lifecycleStage = normalizeLifecycleStage(item.lifecycle_stage || '');

  if (type === 'video' && !familySlug) {
    warnings.push({
      level: 'warn',
      code: 'missing_family_slug',
      message: 'Cette video n\'a pas de family_slug (regroupement conseille).'
    });
  }

  if (PREVIEW_CATEGORIES.has(category) && !sourceUrl) {
    warnings.push({
      level: 'warn',
      code: 'missing_preview_destination',
      message: 'Preview sans destination (source_url) vers la version complete.'
    });
  }

  if (lifecycleStage && !VALID_LIFECYCLE_STAGES.has(lifecycleStage)) {
    warnings.push({
      level: 'warn',
      code: 'invalid_lifecycle_stage',
      message: 'lifecycle_stage invalide. Valeurs: feature, preview-ever, archive.'
    });
  }

  if (sourceUrl) {
    try {
      const u = new URL(sourceUrl);
      if (!/^https?:$/i.test(u.protocol)) {
        warnings.push({
          level: 'warn',
          code: 'invalid_source_url_protocol',
          message: 'source_url doit utiliser http:// ou https://.'
        });
      }
    } catch (e) {
      warnings.push({
        level: 'warn',
        code: 'invalid_source_url',
        message: 'source_url est invalide.'
      });
    }
  }

  return warnings;
}

function withValidation(item) {
  return {
    ...item,
    validation_warnings: buildValidationWarnings(item)
  };
}

// Common tracking query params stripped during URL normalization
const TRACKING_PARAMS = new Set([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'fbclid', 'gclid', 'igshid', 'si', '_ga', 'mc_cid', 'mc_eid',
  'ref', 'source', 'yclid'
]);

// Return a canonical URL suitable for dedup comparison (tracking params removed).
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    TRACKING_PARAMS.forEach(p => u.searchParams.delete(p));
    // Remove trailing slash on non-root paths
    const path = u.pathname.length > 1 ? u.pathname.replace(/\/$/, '') : u.pathname;
    return `${u.protocol}//${u.host}${path}${u.search}${u.hash}`;
  } catch (e) {
    return url.trim().toLowerCase();
  }
}

// Build a canonical dedup key for a media item.
// Returns null when no stable key can be derived.
function buildDedupKey(type, { guids = null, storagePath = null, sourceUrl = null } = {}) {
  if (type === 'video' && Array.isArray(guids) && guids.length > 0) {
    const sorted = guids.filter(Boolean).sort();
    if (sorted.length > 0) return `video:${sorted.join(',')}`;
  }
  if (storagePath) return `photo:${storagePath.replace(/^\//, '').toLowerCase()}`;
  if (sourceUrl) return `link:${normalizeUrl(sourceUrl)}`;
  return null;
}

// Return the first existing item that shares dedupKey (excluding excludeId).
// Returns null when no match found or key is null.
async function checkDuplicate(db, dedupKey, excludeId = null) {
  if (!dedupKey) return null;
  let sql = 'SELECT id, title, type FROM media_items WHERE dedup_key = ?';
  const args = [dedupKey];
  if (excludeId) { sql += ' AND id != ?'; args.push(excludeId); }
  sql += ' LIMIT 1';
  const res = await db.execute({ sql, args });
  return res.rows.length > 0 ? res.rows[0] : null;
}

function httpsRequest(options, body, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function getQuery(req) {
  if (req._parsedQuery && typeof req._parsedQuery === 'object') return req._parsedQuery;
  const host = req.headers?.host || 'localhost';
  const proto = req.headers?.['x-forwarded-proto'] || 'https';
  const url = new URL(req.url || '/', `${proto}://${host}`);
  const parsed = Object.fromEntries(url.searchParams.entries());
  req._parsedQuery = parsed;
  return parsed;
}

function parseBunnyItemsPayload(data) {
  const parsed = JSON.parse(data || '{}');
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.items)) return parsed.items;
  return [];
}

async function fetchBunnyVideos({ libraryId, accessKey }) {
  const headers = { 'AccessKey': accessKey, 'accept': 'application/json' };

  const r = await httpsRequest({
    hostname: 'video.bunnycdn.com',
    path: `/library/${libraryId}/videos?itemsPerPage=1000&orderBy=date`,
    method: 'GET',
    headers
  });
  if (r.status !== 200) throw new Error(`Bunny API error: ${r.status}`);
  return {
    items: parseBunnyItemsPayload(r.data),
    debug: {
      endpoint_used: `/library/${libraryId}/videos?itemsPerPage=1000&orderBy=date`,
      status: r.status
    }
  };
}

function signUrl(url, securityKey, expirationSeconds = 3600) {
  if (!url || !securityKey) return url;
  try {
    const expires = Math.floor(Date.now() / 1000) + expirationSeconds;
    const urlObj = new URL(url);
    const path = urlObj.pathname;
    const toSign = securityKey + path + expires;
    const hash = crypto.createHash('sha256').update(toSign).digest('base64');
    const signature = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${url}?token=${signature}&expires=${expires}`;
  } catch (e) {
    console.error('[admin-api] URL signing failed:', e.message);
    return url;
  }
}

function normalizeBunnyAssetUrl(url, pull, guid, fallbackFilename) {
  const raw = String(url || '').trim();

  if (!raw) {
    return guid ? `${pull}/${guid}/${fallbackFilename}` : '';
  }

  if (/^https?:\/\//i.test(raw)) return raw;
  if (raw.startsWith('//')) return `https:${raw}`;
  if (/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(raw)) return `https://${raw}`;
  if (raw.startsWith('/')) return `${pull}${raw}`;
  return `${pull}/${raw.replace(/^\/+/, '')}`;
}

function signPrivateMediaItem(item) {
  if (!item || !item.is_private || item.type !== 'video') return item;

  const signingKey = readEnv('BUNNY_CDN_SIGNING_KEY', ['BUNNY_TOKEN_KEY', 'BUNNY_SIGNING_KEY', 'BUNNY_PRIVATE_ACCESS_KEY']);
  if (!signingKey) return item;

  const formats = item.formats || {};
  const signedFormats = {};

  for (const [fmt, data] of Object.entries(formats)) {
    if (!data) continue;

    const bunnyUrl = normalizeBunnyAssetUrl(data.bunny_url, PRIVATE.pull, data.guid, 'play_720p.mp4');
    const thumbnailUrl = normalizeBunnyAssetUrl(data.thumbnail_url, PRIVATE.pull, data.guid, 'thumbnail.jpg');

    signedFormats[fmt] = {
      ...data,
      bunny_url: bunnyUrl ? signUrl(bunnyUrl, signingKey, 3600) : bunnyUrl,
      thumbnail_url: thumbnailUrl ? signUrl(thumbnailUrl, signingKey, 86400) : thumbnailUrl
    };
  }

  return {
    ...item,
    formats: signedFormats
  };
}

function computeEnvHealth() {
  const checks = [
    { key: 'ADMIN_TOKEN', aliases: [], required: true },
    { key: 'TURSO_DB_URL', aliases: ['TURSO_DATABASE_URL'], required: true },
    { key: 'TURSO_DB_TOKEN', aliases: ['TURSO_AUTH_TOKEN'], required: true },
    { key: 'BUNNY_PUBLIC_LIBRARY_ID', aliases: ['BUNNY_LIBRARY_ID'], required: false },
    { key: 'BUNNY_PUBLIC_LIBRARY_API_KEY', aliases: ['BUNNY_ACCESS_KEY'], required: false },
    { key: 'BUNNY_PUBLIC_PULL_ZONE_URL', aliases: ['BUNNY_PULL_ZONE'], required: false },
    { key: 'BUNNY_PRIVATE_LIBRARY_ID', aliases: ['BUNNY_PRIVATE_LIBRARY_ID'], required: false },
    { key: 'BUNNY_PRIVATE_LIBRARY_API_KEY', aliases: ['BUNNY_PRIVATE_ACCESS_KEY', 'BUNNY_API_KEY'], required: false },
    { key: 'BUNNY_PRIVATE_PULL_ZONE_URL', aliases: ['BUNNY_PRIVATE_PULL_ZONE', 'BUNNY_PULL_ZONE_HOST'], required: false },
    { key: 'BUNNY_CDN_SIGNING_KEY', aliases: ['BUNNY_TOKEN_KEY', 'BUNNY_SIGNING_KEY'], required: false },
    { key: 'ADMIN_SERVICE_KEY', aliases: ['CHAUD_DEVANT_SERVICE_KEY'], required: false },
    { key: 'WEBHOOK_SECRET_PROJECT_LINKS', aliases: ['PROJECT_LINKS_REVALIDATE_SECRET', 'PROJECT_ROUTES_REVALIDATE_SECRET'], required: false },
    { key: 'WEBHOOK_SECRET_SUPER_VIDEOTHEQUE', aliases: ['SUPER_VIDEOTHEQUE_WEBHOOK_SECRET', 'CATALOG_SYNC_WEBHOOK_SECRET'], required: false },
  ];

  const details = checks.map((row) => {
    const resolved = resolveEnv(row.key, row.aliases);
    return {
      key: row.key,
      required: row.required,
      present: !!resolved.value,
      source: resolved.source,
      used_legacy_alias: resolved.used_legacy_alias,
      aliases: row.aliases,
    };
  });

  const missing_required = details.filter(d => d.required && !d.present).map(d => d.key);
  const using_legacy_aliases = details.filter(d => d.used_legacy_alias).map(d => ({ key: d.key, source: d.source }));

  return {
    ok: missing_required.length === 0,
    strict_mode: ENV_STRICT_MODE,
    missing_required,
    using_legacy_aliases,
    details,
  };
}

function hasEnv(health, key) {
  const row = health.details.find((d) => d.key === key);
  return !!(row && row.present);
}

function getStrictBlockingMissing(action, req) {
  const health = computeEnvHealth();
  const missing = new Set(health.missing_required);

  if (action === 'upload') {
    const body = parseJsonBody(req);
    const type = inferUploadType(body);
    const isPrivate = Boolean(body?.is_private);
    const hasInlinePhoto = Boolean(body?.file);

    if (type === 'photo') {
      // Photo link import does not need Bunny Storage credentials.
      if (hasInlinePhoto) {
        for (const key of ['BUNNY_STORAGE_NAME', 'BUNNY_STORAGE_API_KEY', 'BUNNY_STORAGE_PULL_ZONE_URL']) {
          if (!hasEnv(health, key)) missing.add(key);
        }
      }
    } else {
      // Video upload requires only the selected visibility library.
      if (isPrivate) {
        for (const key of ['BUNNY_PRIVATE_LIBRARY_ID', 'BUNNY_PRIVATE_LIBRARY_API_KEY', 'BUNNY_PRIVATE_PULL_ZONE_URL']) {
          if (!hasEnv(health, key)) missing.add(key);
        }
      } else {
        for (const key of ['BUNNY_PUBLIC_LIBRARY_ID', 'BUNNY_PUBLIC_LIBRARY_API_KEY', 'BUNNY_PUBLIC_PULL_ZONE_URL']) {
          if (!hasEnv(health, key)) missing.add(key);
        }
      }
    }
  }

  if (['sync-videos', 'delete', 'resolve-duplicate'].includes(action)) {
    const forUpload = [
      'BUNNY_PUBLIC_LIBRARY_ID',
      'BUNNY_PUBLIC_LIBRARY_API_KEY',
      'BUNNY_PUBLIC_PULL_ZONE_URL',
      'BUNNY_PRIVATE_LIBRARY_ID',
      'BUNNY_PRIVATE_LIBRARY_API_KEY',
      'BUNNY_PRIVATE_PULL_ZONE_URL',
      'BUNNY_CDN_SIGNING_KEY'
    ];
    for (const key of forUpload) {
      if (!hasEnv(health, key)) missing.add(key);
    }
  }

  return { health, missing: Array.from(missing) };
}

async function actionEnvHealth(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });
  const targetAction = String(getQuery(req).target_action || '').trim();
  const strict = getStrictBlockingMissing(targetAction || 'list', req);
  return res.status(200).json({
    ...strict.health,
    target_action: targetAction || null,
    strict_blocking_missing: strict.missing,
  });
}

async function actionAuth(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const body = parseJsonBody(req);
  const token = String(body.token || '').trim();
  const otp = String(body.otp || '').trim();
  const expected = String(process.env.ADMIN_TOKEN || '').trim();
  const otpCheck = verifyTotp(otp);
  const totpEnabled = otpCheck.required;

  if (totpEnabled) {
    if (!otpCheck.ok) {
      return res.status(401).json({
        error: 'Invalid 2FA code',
        otp_required: true
      });
    }
  } else {
    if (!token || !expected) {
      return res.status(401).json({ error: 'Invalid credentials', otp_required: false });
    }
    const tokenBuf = Buffer.from(token, 'utf8');
    const expectedBuf = Buffer.from(expected, 'utf8');
    if (!(tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf))) {
      return res.status(401).json({ error: 'Invalid credentials', otp_required: false });
    }
  }

  if (!otpCheck.ok) {
    return res.status(401).json({
      error: 'Invalid credentials',
      otp_required: totpEnabled
    });
  }

  const session = createSessionToken();
  return res.status(200).json({
    ok: true,
    token: session.token,
    expires_in: session.expires_in,
    otp_required: totpEnabled
  });
}

// ─── Actions ───

async function actionList(req, res, db) {
  const t0 = Date.now();
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const { type, category, source_type, status, search, duplicate_status } = getQuery(req);
  let sql = 'SELECT * FROM media_items';
  const conditions = [];
  const params = [];

  if (type) { conditions.push('type = ?'); params.push(type); }
  if (category) { conditions.push('category = ?'); params.push(category); }
  if (source_type) { conditions.push('source_type = ?'); params.push(source_type); }
  if (status) { conditions.push('status = ?'); params.push(status); }
  if (duplicate_status) { conditions.push('duplicate_status = ?'); params.push(duplicate_status); }
  if (search) {
    conditions.push('(title LIKE ? OR description LIKE ? OR tags LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (conditions.length > 0) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY date_uploaded DESC';

  const result = await db.execute({ sql, args: params });
  console.log(`[list] ${result.rows.length} rows in ${Date.now() - t0}ms`);
  const items = result.rows.map(parseRow).map(withRouteFields).map(withValidation).map(signPrivateMediaItem);
  res.status(200).json(items);
}

/**
 * Fire-and-forget: notifie les plateformes consommatrices quand un item est sauvegardé.
 * - project routes: invalide le cache via POST /api/revalidate?slug=X
 * - videotheque / viewer-only: déclenche un sync via POST /api/webhook/sync
 * Ne bloque jamais l'appelant (erreurs loguées silencieusement).
 */
function notifyDestinations(destinations) {
  const dests = Array.isArray(destinations) ? destinations : [];
  if (dests.length === 0) return;

  const projectRoutesUrl = (process.env.PROJECT_ROUTES_URL || '').trim().replace(/\/$/, '');
  const revalidateSecret = readEnv('WEBHOOK_SECRET_PROJECT_LINKS', ['PROJECT_LINKS_REVALIDATE_SECRET', 'PROJECT_ROUTES_REVALIDATE_SECRET']);
  const catalogSyncUrl = (process.env.CATALOG_SYNC_URL || '').trim().replace(/\/$/, '');
  const viewerSyncUrl = (process.env.VIEWER_SYNC_URL || '').trim().replace(/\/$/, '');
  const catalogWebhookSecret = readEnv('WEBHOOK_SECRET_SUPER_VIDEOTHEQUE', ['SUPER_VIDEOTHEQUE_WEBHOOK_SECRET', 'CATALOG_SYNC_WEBHOOK_SECRET']);

  const slugs = [...new Set(
    dests.filter(d => d.startsWith('project:')).map(d => d.slice('project:'.length))
  )];

  if (projectRoutesUrl && revalidateSecret && slugs.length > 0) {
    for (const slug of slugs) {
      fetch(`${projectRoutesUrl}/api/revalidate?slug=${encodeURIComponent(slug)}`, {
        method: 'POST',
        headers: { 'x-revalidate-secret': revalidateSecret },
      }).catch(e => console.error(`[notify] project route revalidate failed (slug=${slug}):`, e.message));
    }
  }

  if (catalogWebhookSecret && (dests.includes('catalog') || dests.includes('super-videotheque') || dests.includes('viewer-only'))) {
    const targets = [catalogSyncUrl, viewerSyncUrl].filter(Boolean);
    for (const target of targets) {
      fetch(`${target}/api/webhook/sync`, {
        method: 'POST',
        headers: { 'x-webhook-secret': catalogWebhookSecret },
      }).catch(e => console.error(`[notify] sync webhook failed (${target}):`, e.message));
    }
  }
}

async function actionUpdate(req, res, db) {
  if (req.method !== 'PATCH' && req.method !== 'PUT') return res.status(405).json({ error: 'PATCH or PUT only' });

  const { id } = getQuery(req);
  if (!id) return res.status(400).json({ error: 'Missing ?id= parameter' });

  const body = req.body;
  const existingResult = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (existingResult.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  const existingItem = parseRow(existingResult.rows[0]);
  const fields = [];
  const values = [];

  const textFields = ['title', 'description', 'category', 'date_filmed',
    'primary_format', 'source_url', 'notes', 'family_slug', 'bunny_library', 'storage_path',
    'pricing_mode', 'lifecycle_stage', 'cta_label', 'quality_level'];
  for (const key of textFields) {
    if (body[key] !== undefined) {
      let value = body[key];
      if (key === 'family_slug') value = normalizeFamilySlug(value);
      if (key === 'pricing_mode') value = normalizePricingMode(value);
      if (key === 'lifecycle_stage') value = normalizeLifecycleStage(value);
      if (key === 'quality_level') value = normalizeQualityLevel(value);
      fields.push(`${key} = ?`);
      values.push(value);
    }
  }

  if (body.sort_order !== undefined) { fields.push('sort_order = ?'); values.push(Number(body.sort_order) || 0); }
  if (body.is_featured !== undefined) { fields.push('is_featured = ?'); values.push(body.is_featured ? 1 : 0); }

  if (body.duration !== undefined) { fields.push('duration = ?'); values.push(body.duration); }
  if (body.file_size !== undefined) { fields.push('file_size = ?'); values.push(body.file_size); }

  for (const key of ['is_private', 'is_locked']) {
    if (body[key] !== undefined) { fields.push(`${key} = ?`); values.push(body[key] ? 1 : 0); }
  }

  for (const key of ['formats', 'social_meta']) {
    if (body[key] !== undefined) { fields.push(`${key} = ?`); values.push(JSON.stringify(body[key])); }
  }

  if (body.tags !== undefined || body.destinations !== undefined || body.route_tags !== undefined) {
    const inputTags = body.tags !== undefined ? body.tags : existingItem.tags;
    const inputDestinations = body.destinations !== undefined ? body.destinations : existingItem.destinations;
    const routeTags = buildRouteTags({ tags: inputTags, destinations: inputDestinations, route_tags: body.route_tags });
    const contentTags = parseArraySafe(inputTags).filter(t => !isRouteTag(t));
    const nextTags = [...new Set([...contentTags, ...routeTags])];
    const nextDestinations = buildDestinationsFromRouteTags(routeTags);
    fields.push('tags = ?');
    values.push(JSON.stringify(nextTags));
    fields.push('destinations = ?');
    values.push(JSON.stringify(nextDestinations));
  }

  if (body.status !== undefined) { fields.push('status = ?'); values.push(body.status); }
  fields.push("updated_at = datetime('now')");
  values.push(id);

  await db.execute({ sql: `UPDATE media_items SET ${fields.join(', ')} WHERE id = ?`, args: values });

  const result = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  const updatedItem = withValidation(withRouteFields(parseRow(result.rows[0])));
  notifyDestinations(updatedItem.destinations);
  res.status(200).json(updatedItem);
}

async function actionDelete(req, res, db) {
  if (req.method !== 'DELETE') return res.status(405).json({ error: 'DELETE only' });

  const query = getQuery(req);
  const { id } = query;
  if (!id) return res.status(400).json({ error: 'Missing ?id= parameter' });

  const result = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });

  const item = result.rows[0];
  const cdnResults = [];

  if (query.deleteCdn === 'true') {
    if (item.type === 'video') {
      ensureBunnyVideoConfig(item.bunny_library === 'private' ? 'private' : 'public');
      const formats = JSON.parse(item.formats || '{}');
      const lib = item.bunny_library === 'private' ? PRIVATE : PUBLIC;
      for (const [, data] of Object.entries(formats)) {
        if (data && data.guid) {
          const r = await httpsRequest({
            hostname: 'video.bunnycdn.com',
            path: `/library/${lib.id}/videos/${data.guid}`,
            method: 'DELETE',
            headers: { 'AccessKey': lib.key }
          }).catch(e => ({ error: e.message }));
          cdnResults.push(r);
        }
      }
    } else if (item.type === 'photo' && item.storage_path) {
      ensureBunnyStorageConfig();
      const r = await httpsRequest({
        hostname: 'ny.storage.bunnycdn.com',
        path: `/${STORAGE.name}${item.storage_path}`,
        method: 'DELETE',
        headers: { 'AccessKey': STORAGE.password }
      }).catch(e => ({ error: e.message }));
      cdnResults.push(r);
    }
  }

  await db.execute({ sql: 'DELETE FROM media_items WHERE id = ?', args: [id] });
  res.status(200).json({ deleted: true, id, cdnResults });
}

async function actionTagBoxes(req, res, db) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });
  const result = await db.execute({
    sql: 'SELECT id, name, slug, payload, created_at, updated_at FROM tag_boxes ORDER BY name COLLATE NOCASE ASC',
    args: []
  });
  res.status(200).json({ items: result.rows.map(parseTagBoxRow) });
}

async function actionSaveTagBox(req, res, db) {
  if (req.method !== 'POST' && req.method !== 'PUT') return res.status(405).json({ error: 'POST or PUT only' });
  const body = req.body || {};
  const name = String(body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name required' });

  const id = String(body.id || '').trim() || slugify(name) || `box-${Date.now()}`;
  const slug = normalizeFamilySlug(body.slug || name) || id;
  const payload = body.payload && typeof body.payload === 'object' ? body.payload : {};

  const exists = await db.execute({ sql: 'SELECT id FROM tag_boxes WHERE id = ?', args: [id] });
  if (exists.rows.length > 0) {
    await db.execute({
      sql: 'UPDATE tag_boxes SET name = ?, slug = ?, payload = ?, updated_at = datetime(\'now\') WHERE id = ?',
      args: [name, slug, JSON.stringify(payload), id]
    });
  } else {
    await db.execute({
      sql: 'INSERT INTO tag_boxes (id, name, slug, payload, updated_at) VALUES (?, ?, ?, ?, datetime(\'now\'))',
      args: [id, name, slug, JSON.stringify(payload)]
    });
  }

  const result = await db.execute({
    sql: 'SELECT id, name, slug, payload, created_at, updated_at FROM tag_boxes WHERE id = ?',
    args: [id]
  });
  if (!result.rows.length) return res.status(500).json({ error: 'Could not save tag box' });
  res.status(200).json(parseTagBoxRow(result.rows[0]));
}

async function actionDeleteTagBox(req, res, db) {
  if (req.method !== 'DELETE') return res.status(405).json({ error: 'DELETE only' });
  const { id } = getQuery(req);
  if (!id) return res.status(400).json({ error: 'Missing ?id= parameter' });
  await db.execute({ sql: 'DELETE FROM tag_boxes WHERE id = ?', args: [id] });
  res.status(200).json({ deleted: true, id });
}

// Fetch Open Graph + social card + favicon metadata from a URL.
// The og:*, twitter:*, and similar meta tag conventions are web standards
// supported by most websites (blogs, e-commerce, CMS, etc.)
async function fetchOpenGraph(url) {
  try {
    if (!url.startsWith('http')) return {};
    const resp = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(8000)
    });
    if (!resp.ok) return {};
    const html = await resp.text();
    const headEnd = html.indexOf('</head>');
    const head = headEnd > 0 ? html.substring(0, headEnd + 7) : html.substring(0, 50000);
    const og = {};

    // og:* meta tags (both attribute orders)
    const ogRegex1 = /<meta\s+[^>]*(?:property|name)\s*=\s*["']og:([^"']+)["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*\/?>/gi;
    const ogRegex2 = /<meta\s+[^>]*content\s*=\s*["']([^"']*)["'][^>]*(?:property|name)\s*=\s*["']og:([^"']+)["'][^>]*\/?>/gi;
    let m;
    while ((m = ogRegex1.exec(head)) !== null) og[m[1]] = m[2];
    while ((m = ogRegex2.exec(head)) !== null) og[m[2]] = m[1];

    // twitter:* meta tags as fallback for image/title/description
    const twRegex1 = /<meta\s+[^>]*name\s*=\s*["']twitter:([^"']+)["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*\/?>/gi;
    const twRegex2 = /<meta\s+[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']twitter:([^"']+)["'][^>]*\/?>/gi;
    while ((m = twRegex1.exec(head)) !== null) {
      const key = m[1] === 'image:src' ? 'image' : m[1];
      if (!og[key]) og[key] = m[2];
    }
    while ((m = twRegex2.exec(head)) !== null) {
      const key = m[2] === 'image:src' ? 'image' : m[2];
      if (!og[key]) og[key] = m[1];
    }

    // Fallback: <title> tag if og:title is still missing
    if (!og.title) {
      const titleMatch = /<title[^>]*>([^<]+)<\/title>/i.exec(head);
      if (titleMatch) og.title = titleMatch[1].trim();
    }

    // Fallback: meta description
    if (!og.description) {
      const descRegex = /<meta\s+[^>]*name\s*=\s*["']description["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*\/?>/i;
      const descMatch = descRegex.exec(head);
      if (descMatch) og.description = descMatch[1];
    }

    // Fallback: apple-touch-icon > icon > shortcut icon > first img
    if (!og.image) {
      const linkPatterns = [
        /<link\s+[^>]*rel\s*=\s*["']apple-touch-icon[^"']*["'][^>]*href\s*=\s*["']([^"']+)["']/i,
        /<link\s+[^>]*rel\s*=\s*["'](?:shortcut )?icon["'][^>]*href\s*=\s*["']([^"']+)["']/i,
        /<link\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["'](?:shortcut )?icon["']/i
      ];
      for (const p of linkPatterns) {
        const lm = p.exec(head);
        if (lm) { og.image = lm[1]; break; }
      }
    }

    // Last resort: first <img src> in body (limited scan)
    if (!og.image) {
      const bodyStart = headEnd > 0 ? headEnd : 0;
      const body = html.substring(bodyStart, bodyStart + 30000);
      const imgMatch = /<img\s+[^>]*src\s*=\s*["']([^"']+)["']/i.exec(body);
      if (imgMatch) og.image = imgMatch[1];
    }

    return og;
  } catch (e) {
    console.log('OG fetch failed for', url, e.message);
    return {};
  }
}

async function actionImportLink(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { url, title, type, description, tags, category, notes } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing url' });

  // Fetch Open Graph + social meta (og:*, twitter:*, favicon, first img) in one pass
  const og = url.startsWith('http') ? await fetchOpenGraph(url) : {};

  const hasVideoExt = /\.(mp4|mov|webm|avi|mkv)(\?|$)/i.test(url);
  const mediaType = type || (og.type === 'video' || og['video:url'] || hasVideoExt ? 'video' : 'photo');
  const mediaTitle = (title || og.title || url.split('/').pop().split('?')[0] || 'Import').trim();
  const mediaDescription = description || og.description || '';

  let baseId = slugify(mediaTitle) || 'import';
  let id = baseId;
  let counter = 1;
  while (true) {
    const check = await db.execute({ sql: 'SELECT id FROM media_items WHERE id = ?', args: [id] });
    if (check.rows.length === 0) break;
    id = `${baseId}-${++counter}`;
  }

  // Build thumbnail from scraped metadata (og:image, twitter:image, apple-touch-icon, favicon, first <img>)
  let thumbUrl = null;
  if (og.image) {
    try {
      // Resolve relative URLs against the source URL
      thumbUrl = og.image.startsWith('http') ? og.image : new URL(og.image, url).href;
    } catch (e) {
      thumbUrl = og.image;
    }
  }

  // Last-resort fallback: Google's public favicon service (works for any public domain)
  if (!thumbUrl && url.startsWith('http')) {
    try {
      const u = new URL(url);
      thumbUrl = `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=256`;
    } catch (e) { /* invalid URL */ }
  }

  // Extract domain for display
  let domain = '';
  try { domain = new URL(url).hostname.replace(/^www\./, ''); } catch (e) { console.log('[import-link] Could not parse URL for domain extraction:', url); }

  const siteName = og.site_name || domain || '';

  const linkMeta = {
    thumbnail_url: thumbUrl || null,
    source_url: url,
    site_name: siteName,
    domain,
    description: og.description || '',
    og_type: og.type || 'website'
  };

  // Always store link metadata (even without a thumbnail)
  const formats = JSON.stringify({ link: linkMeta });

  // ─── Dedup check ───
  const dedupKey = buildDedupKey('link', { sourceUrl: url });
  const dupMatch = await checkDuplicate(db, dedupKey);
  const duplicateOf = dupMatch ? dupMatch.id : null;
  const duplicateStatus = dupMatch ? 'duplicate' : null;

  await db.execute({
    sql: `INSERT INTO media_items (id, type, title, description, tags, category, status, source_type, source_url, formats, notes, dedup_key, duplicate_of, duplicate_status, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, 'published', 'link', ?, ?, ?, ?, ?, ?, datetime('now'))`,
    args: [id, mediaType, mediaTitle, mediaDescription, JSON.stringify(tags || []), category || '', url, formats, notes || '', dedupKey, duplicateOf, duplicateStatus]
  });

  const result = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  const item = parseRow(result.rows[0]);
  if (dupMatch) {
    item.is_duplicate = true;
    item.existing_id = dupMatch.id;
    item.existing_title = dupMatch.title;
  }
  res.status(201).json(item);
}

async function actionUpload(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const body = req.body;
  const type = inferUploadType(body);
  const itemStatus = inferUploadStatus(body);
  const title = (body.title || 'Sans titre').trim();
  const format = body.format || '16x9';
  const isPrivate = !!body.is_private;
  const familySlug = normalizeFamilySlug(body.family_slug || body.family || title);
  const pricingMode = normalizePricingMode(body.pricing_mode || '');
  const lifecycleStage = normalizeLifecycleStage(body.lifecycle_stage || '');
  const ctaLabel = String(body.cta_label || '').trim();
  const qualityLevel = normalizeQualityLevel(body.quality_level || 'draft');
  const sortOrder = Number(body.sort_order) || 0;
  const isFeatured = !!body.is_featured;
  const routeTags = buildRouteTags({ tags: body.tags, destinations: body.destinations, route_tags: body.route_tags });
  const destinations = buildDestinationsFromRouteTags(routeTags);
  const contentTags = parseArraySafe(body.tags).filter(t => !isRouteTag(t));
  const persistedTags = [...new Set([...contentTags, ...routeTags])];

  let baseId = slugify(title) || 'media';
  let id = baseId;
  let counter = 1;
  while (true) {
    const check = await db.execute({ sql: 'SELECT id FROM media_items WHERE id = ?', args: [id] });
    if (check.rows.length === 0) break;
    id = `${baseId}-${++counter}`;
  }

  const result = { id, type };

  if (type === 'video') {
    ensureBunnyVideoConfig(isPrivate ? 'private' : 'public');
    const lib = isPrivate ? PRIVATE : PUBLIC;
    const bunnyTitle = `${id} (${format})`;

    const videoData = JSON.stringify({ title: bunnyTitle });
    const bunnyRes = await httpsRequest({
      hostname: 'video.bunnycdn.com',
      path: `/library/${lib.id}/videos`,
      method: 'POST',
      headers: { 'AccessKey': lib.key, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(videoData) }
    }, videoData);

    if (bunnyRes.status < 200 || bunnyRes.status >= 300) {
      throw new Error(`Bunny Video API ${bunnyRes.status}: ${bunnyRes.data}`);
    }
    const bunnyVideo = JSON.parse(bunnyRes.data);

    const expirationTime = Math.floor(Date.now() / 1000) + 7200;
    const signature = crypto.createHash('sha256')
      .update(lib.id + lib.key + expirationTime + bunnyVideo.guid)
      .digest('hex');

    const formats = {};
    formats[format] = {
      guid: bunnyVideo.guid,
      bunny_url: `${lib.pull}/${bunnyVideo.guid}/play_720p.mp4`,
      thumbnail_url: `${lib.pull}/${bunnyVideo.guid}/thumbnail.jpg`
    };

    // ─── Dedup check (based on Bunny GUID) ───
    const dedupKey = buildDedupKey('video', { guids: [bunnyVideo.guid] });
    const dupMatch = await checkDuplicate(db, dedupKey);
    const duplicateOf = dupMatch ? dupMatch.id : null;
    const duplicateStatus = dupMatch ? 'duplicate' : null;

    await db.execute({
      sql: `INSERT INTO media_items (id, type, title, description, tags, category, date_filmed, is_private, is_locked, status, primary_format, formats, source_type, source_url, notes, family_slug, bunny_library, pricing_mode, lifecycle_stage, cta_label, quality_level, sort_order, is_featured, dedup_key, duplicate_of, duplicate_status, destinations, updated_at)
        VALUES (?, 'video', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      args: [
        id, title, body.description || '',
        JSON.stringify(persistedTags), body.category || '',
        body.date_filmed || null,
        isPrivate ? 1 : 0, isPrivate ? 1 : 0,
        itemStatus,
        format, JSON.stringify(formats),
        body.source_type || 'upload', body.source_url || '', body.notes || '', familySlug,
        isPrivate ? 'private' : 'public',
        pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
        dedupKey, duplicateOf, duplicateStatus, JSON.stringify(destinations)
      ]
    });

    result.status = itemStatus;

    result.guid = bunnyVideo.guid;
    result.upload = {
      endpoint: 'https://video.bunnycdn.com/tusupload',
      headers: {
        AuthorizationSignature: signature,
        AuthorizationExpire: expirationTime.toString(),
        VideoId: bunnyVideo.guid,
        LibraryId: lib.id,
      }
    };
    if (dupMatch) {
      result.is_duplicate = true;
      result.existing_id = dupMatch.id;
      result.existing_title = dupMatch.title;
    }

  } else if (type === 'photo') {
    const fileData = body.file;
    const fileName = body.fileName || `${id}.jpg`;
    const folder = body.isPromo ? '/promo/' : '/';

    if (fileData) {
      ensureBunnyStorageConfig();
      const buffer = Buffer.from(fileData, 'base64');
      await httpsRequest({
        hostname: 'ny.storage.bunnycdn.com',
        path: `/${STORAGE.name}${folder}${fileName}`,
        method: 'PUT',
        headers: { 'AccessKey': STORAGE.password, 'Content-Type': 'application/octet-stream', 'Content-Length': buffer.length }
      }, buffer);

      const url = `${STORAGE.pullZone}${folder}${fileName}`;
      const photoStoragePath = `${folder}${fileName}`;
      const photoDedupKey = buildDedupKey('photo', { storagePath: photoStoragePath });
      const photoDupMatch = await checkDuplicate(db, photoDedupKey);
      await db.execute({
          sql: `INSERT INTO media_items (id, type, title, description, tags, category, date_filmed, is_private, is_locked, status, source_type, storage_path, file_size, notes, family_slug, pricing_mode, lifecycle_stage, cta_label, quality_level, sort_order, is_featured, dedup_key, duplicate_of, duplicate_status, destinations, updated_at)
            VALUES (?, 'photo', ?, ?, ?, ?, ?, 0, 0, ?, 'upload', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        args: [
          id, title, body.description || '',
          JSON.stringify(persistedTags), body.category || '',
          body.date_filmed || null,
          itemStatus,
          photoStoragePath, buffer.length, body.notes || '', familySlug,
            pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
          photoDedupKey,
          photoDupMatch ? photoDupMatch.id : null,
          photoDupMatch ? 'duplicate' : null,
          JSON.stringify(destinations)
        ]
      });
      result.url = url;
      result.status = itemStatus;
      if (photoDupMatch) {
        result.is_duplicate = true;
        result.existing_id = photoDupMatch.id;
        result.existing_title = photoDupMatch.title;
      }
    } else {
      const linkDedupKey = buildDedupKey('link', { sourceUrl: body.source_url });
      const linkDupMatch = await checkDuplicate(db, linkDedupKey);
      await db.execute({
          sql: `INSERT INTO media_items (id, type, title, description, tags, category, date_filmed, status, source_type, source_url, notes, family_slug, pricing_mode, lifecycle_stage, cta_label, quality_level, sort_order, is_featured, dedup_key, duplicate_of, duplicate_status, destinations, updated_at)
            VALUES (?, 'photo', ?, ?, ?, ?, ?, ?, 'link', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        args: [
          id, title, body.description || '',
          JSON.stringify(persistedTags), body.category || '',
          body.date_filmed || null,
          itemStatus,
          body.source_url || '', body.notes || '', familySlug,
            pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
          linkDedupKey,
          linkDupMatch ? linkDupMatch.id : null,
          linkDupMatch ? 'duplicate' : null,
          JSON.stringify(destinations)
        ]
      });
      result.status = itemStatus;
      if (linkDupMatch) {
        result.is_duplicate = true;
        result.existing_id = linkDupMatch.id;
        result.existing_title = linkDupMatch.title;
      }
    }
  }

  const inserted = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (inserted.rows.length > 0) {
    result.validation_warnings = buildValidationWarnings(parseRow(inserted.rows[0]));
  }
  notifyDestinations(destinations);
  res.status(201).json(result);
}

async function actionMigrateShowcase(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const showcasePath = path.join(__dirname, '..', 'showcase_v2.json');
  const showcase = JSON.parse(fs.readFileSync(showcasePath, 'utf8'));

  let imported = 0;
  let skipped = 0;
  const errors = [];

  for (const item of showcase) {
    try {
      const existing = await db.execute({ sql: 'SELECT id FROM media_items WHERE id = ?', args: [item.id] });
      if (existing.rows.length > 0) { skipped++; continue; }

      const formats = {};
      for (const [fmt, url] of Object.entries(item.bunny_urls || {})) {
        formats[fmt] = {
          bunny_url: url,
          guid: item.guids?.[fmt] || item.guid || '',
          thumbnail_url: item.thumbnails?.[fmt] || ''
        };
      }

      const primaryFormat = item.primary_format || Object.keys(item.bunny_urls || {})[0] || '16x9';

      await db.execute({
        sql: `INSERT INTO media_items (id, type, title, description, tags, is_private, is_locked, status, primary_format, formats, bunny_library, source_type, updated_at)
              VALUES (?, 'video', ?, ?, ?, ?, ?, 'published', ?, ?, ?, 'monitor', ?)`,
        args: [
          item.id, item.title || item.id, item.description || '',
          JSON.stringify(item.tags || []),
          item.is_private ? 1 : 0, item.is_private ? 1 : 0,
          primaryFormat, JSON.stringify(formats),
          item.is_private ? 'private' : 'public',
          item.updated_at || new Date().toISOString()
        ]
      });
      imported++;
    } catch (err) {
      errors.push({ id: item.id, error: err.message });
    }
  }

  res.status(200).json({ imported, skipped, total: showcase.length, errors });
}

async function actionSyncPhotos(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  ensureBunnyStorageConfig();

  // ─── Fetch listings from Bunny Storage ───
  function fetchBunnyFiles(storageName, password, filePath) {
    return new Promise((resolve, reject) => {
      const r = https.request({
        hostname: 'ny.storage.bunnycdn.com', port: 443,
        path: `/${storageName}${filePath}`, method: 'GET',
        headers: { 'AccessKey': password, 'Accept': 'application/json' }
      }, (resp) => {
        let data = '';
        if (resp.statusCode === 404) return resolve([]);
        if (resp.statusCode !== 200) return reject(new Error(`Status: ${resp.statusCode}`));
        resp.on('data', c => data += c);
        resp.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
      });
      r.setTimeout(30000, () => r.destroy(new Error('Bunny Storage timeout')));
      r.on('error', reject);
      r.end();
    });
  }

  let feedFiles, promoFiles;
  try {
    [feedFiles, promoFiles] = await Promise.all([
      fetchBunnyFiles(STORAGE.name, STORAGE.password, '/'),
      fetchBunnyFiles(STORAGE.name, STORAGE.password, '/promo/')
    ]);
  } catch (err) {
    console.error('[sync-photos] Bunny fetch error:', err.message);
    return res.status(502).json({ error: `Bunny fetch failed: ${err.message}` });
  }

  const imageFilter = f => !f.IsDirectory && /\.(jpg|jpeg|png|webp|gif)$/i.test(f.ObjectName);

  // ─── EDITORIAL fields — never overwritten by sync ───
  // title, description, tags, category, date_filmed, status,
  // platforms_published, is_private, is_locked, notes
  // SOURCE fields updated by sync: file_size, last_synced_at, external_updated_at
  let imported = 0, updated_source = 0, unchanged = 0, removed = 0;
  const allPhotoIds = new Set();

  async function processPhotoFile(f, storagePath, category, idPrefix) {
    const id = slugify(`${idPrefix}${f.ObjectName}`) || `photo-${f.Guid}`;
    allPhotoIds.add(id);

    const existing = await db.execute({ sql: 'SELECT id, file_size FROM media_items WHERE id = ?', args: [id] });

    if (existing.rows.length > 0) {
      const row = existing.rows[0];
      if ((row.file_size || 0) !== (f.Length || 0)) {
        // File size changed: update source-managed fields only
        await db.execute({
          sql: `UPDATE media_items
                SET file_size = ?, last_synced_at = datetime('now'), external_updated_at = ?, updated_at = datetime('now')
                WHERE id = ?`,
          args: [f.Length, f.DateCreated, id]
        });
        updated_source++;
      } else {
        // No source changes: only stamp the sync timestamp
        await db.execute({
          sql: `UPDATE media_items SET last_synced_at = datetime('now') WHERE id = ?`,
          args: [id]
        });
        unchanged++;
      }
      return;
    }

    // New photo: insert as published (auto-sync from Bunny mirrors reality)
    const photoDedupKey = buildDedupKey('photo', { storagePath });
    const photoDupMatch = await checkDuplicate(db, photoDedupKey, id);
    await db.execute({
      sql: `INSERT INTO media_items
              (id, type, title, category, status, source_type, storage_path, file_size,
               dedup_key, duplicate_of, duplicate_status,
               last_synced_at, external_updated_at, updated_at)
            VALUES (?, 'photo', ?, ?, 'published', 'sync', ?, ?, ?, ?, ?, datetime('now'), ?, datetime('now'))`,
      args: [
        id, f.ObjectName, category, storagePath, f.Length,
        photoDedupKey,
        photoDupMatch ? photoDupMatch.id : null,
        photoDupMatch ? 'duplicate' : null,
        f.DateCreated
      ]
    });
    imported++;
  }

  for (const f of feedFiles.filter(imageFilter)) {
    try {
      await processPhotoFile(f, `/${f.ObjectName}`, '', '');
    } catch (err) {
      console.error(`[sync-photos] Error processing feed/${f.ObjectName}:`, err.message);
    }
  }

  for (const f of promoFiles.filter(imageFilter)) {
    try {
      await processPhotoFile(f, `/promo/${f.ObjectName}`, 'promo', 'promo-');
    } catch (err) {
      console.error(`[sync-photos] Error processing promo/${f.ObjectName}:`, err.message);
    }
  }

  // ─── Orphan cleanup: remove photos that no longer exist on Bunny ───
  // Restricted to source_type='sync' (never auto-deletes manually uploaded photos)
  const dbPhotos = await db.execute({
    sql: "SELECT id FROM media_items WHERE type = 'photo' AND source_type IN ('sync', 'monitor')",
    args: []
  });
  for (const row of dbPhotos.rows) {
    if (!allPhotoIds.has(row.id)) {
      await db.execute({ sql: 'DELETE FROM media_items WHERE id = ?', args: [row.id] });
      removed++;
    }
  }

  console.log(`[sync-photos] feed=${feedFiles.filter(imageFilter).length} promo=${promoFiles.filter(imageFilter).length} imported=${imported} updated_source=${updated_source} unchanged=${unchanged} removed=${removed}`);
  res.status(200).json({ imported, updated_source, unchanged, removed });
}

async function actionSyncVideos(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  ensureBunnyVideoConfig('public');
  ensureBunnyVideoConfig('private');

  // ─── Fetch all videos from Bunny Stream (public + private) ───
  let bunnyItems = [];
  let publicFetchDebug = {};
  try {
    const publicFetch = await fetchBunnyVideos({ libraryId: PUBLIC.id, accessKey: PUBLIC.key });
    bunnyItems = publicFetch.items || [];
    publicFetchDebug = {
      fetch: publicFetch.debug,
      mode: 'full-library'
    };

    // Dedup by Bunny guid.
    const byGuid = new Map();
    for (const item of bunnyItems) {
      if (!item || !item.guid) continue;
      if (!byGuid.has(item.guid)) byGuid.set(item.guid, item);
    }
    bunnyItems = Array.from(byGuid.values());
    publicFetchDebug.total_items_after_dedup = bunnyItems.length;
  } catch (err) {
    console.error('[sync-videos] Bunny fetch error:', err.message);
    return res.status(502).json({ error: `Bunny fetch failed: ${err.message}` });
  }

  let bunnyPrivateItems = [];
  let privateFetchDebug = {};
  try {
    const privateFetch = await fetchBunnyVideos({ libraryId: PRIVATE.id, accessKey: PRIVATE.key });
    bunnyPrivateItems = privateFetch.items || [];
    privateFetchDebug = {
      fetch: privateFetch.debug,
      mode: 'full-library'
    };

    // Dedup by Bunny guid.
    const byGuid = new Map();
    for (const item of bunnyPrivateItems) {
      if (!item || !item.guid) continue;
      if (!byGuid.has(item.guid)) byGuid.set(item.guid, item);
    }
    bunnyPrivateItems = Array.from(byGuid.values());
    privateFetchDebug.total_items_after_dedup = bunnyPrivateItems.length;
  } catch (err) {
    console.warn('[sync-videos] Private Bunny fetch (non-fatal):', err.message);
    privateFetchDebug = { endpoint_used: null, status: 'error', error: err.message };
  }

  // ─── Group individual video files into multi-format projects ───
  // Convention: Bunny title "my-video (16x9)" → project "my-video", format "16x9"
  // Be tolerant to naming variants and avoid silent overwrites when format labels collide.
  function groupProjects(items, lib) {
    function ratioFormat(width, height) {
      const w = Number(width || 0);
      const h = Number(height || 0);
      if (!w || !h) return '';
      const ratio = w / h;
      if (Math.abs(ratio - (16 / 9)) < 0.08) return '16x9';
      if (Math.abs(ratio - (9 / 16)) < 0.08) return '9x16';
      if (Math.abs(ratio - 1) < 0.08) return '1x1';
      return `${Math.round(w)}x${Math.round(h)}`;
    }

    function parseProjectAndFormat(title, width, height) {
      const safeTitle = String(title || '').trim();
      if (!safeTitle) return { pid: 'untitled', fmt: ratioFormat(width, height) || '16x9' };

      const normalized = safeTitle.replace(/\s+/g, ' ').trim();
      const parenMatch = normalized.match(/^(.*?)\s*\(([^)]+)\)\s*$/);
      if (parenMatch) {
        const pid = (parenMatch[1] || '').trim() || normalized;
        const fmtRaw = (parenMatch[2] || '').trim().toLowerCase();
        const fmt = fmtRaw
          .replace(/\s+/g, '')
          .replace(/^vertical$/, '9x16')
          .replace(/^portrait$/, '9x16')
          .replace(/^horizontal$/, '16x9')
          .replace(/^square$/, '1x1');
        return { pid, fmt: fmt || ratioFormat(width, height) || '16x9' };
      }

      return { pid: normalized, fmt: ratioFormat(width, height) || '16x9' };
    }

    const projs = {};
    for (const v of items) {
      const { pid, fmt } = parseProjectAndFormat(v.title, v.width, v.height);
      if (!projs[pid]) {
        projs[pid] = {
          id: pid,
          formats: {},
          dateCreated: v.dateCreated,
          category: null,
        };
      }
      const baseFmt = String(fmt || '16x9').trim() || '16x9';
      let finalFmt = baseFmt;
      let i = 2;
      while (projs[pid].formats[finalFmt] && projs[pid].formats[finalFmt].guid !== v.guid) {
        finalFmt = `${baseFmt}-${i}`;
        i++;
      }

      projs[pid].formats[finalFmt] = {
        bunny_url: `${lib.pull}/${v.guid}/play_720p.mp4`,
        guid: v.guid,
        thumbnail_url: `${lib.pull}/${v.guid}/${v.thumbnailFileName || 'thumbnail.jpg'}`,
        length: v.length, width: v.width, height: v.height, size: v.storageSize
      };
      if (new Date(v.dateCreated) > new Date(projs[pid].dateCreated)) projs[pid].dateCreated = v.dateCreated;
    }
    return projs;
  }

  const projects = groupProjects(bunnyItems, PUBLIC);
  const privateProjects = groupProjects(bunnyPrivateItems, PRIVATE);

  function buildDefaultRouting({ category, bunnyLibrary }) {
    const cat = String(category || '').trim().toLowerCase();
    const lib = String(bunnyLibrary || '').trim().toLowerCase();
    const destinations = new Set();

    if (lib === 'private' || cat === 'full-movie' || cat === 'short-video' || cat === 'preview') {
      destinations.add('super-videotheque');
    } else {
      destinations.add('super-videotheque');
      destinations.add('viewer-only');
    }

    return {
      destinations: Array.from(destinations),
      routeTags: Array.from(destinations).map(d => `route:${d}`),
    };
  }

  // ─── Detect meaningful source-field changes ───
  // Compares format keys, guids, and sizes — order-independent.
  function formatsChanged(newFmts, existingFmts) {
    const newKeys = Object.keys(newFmts).sort();
    const oldKeys = Object.keys(existingFmts).sort();
    if (newKeys.join(',') !== oldKeys.join(',')) return true;
    for (const key of newKeys) {
      if ((newFmts[key]?.guid || '') !== (existingFmts[key]?.guid || '')) return true;
      if ((newFmts[key]?.size || 0) !== (existingFmts[key]?.size || 0)) return true;
    }
    return false;
  }

  // ─── EDITORIAL fields — never overwritten by sync ───
  // title, description, tags, category, date_filmed, status,
  // platforms_published, is_private, is_locked, notes, primary_format
  // SOURCE fields updated by sync: formats, duration, file_size,
  //   last_synced_at, external_updated_at
  let imported = 0, updated_source = 0, unchanged = 0, removed = 0;
  const details = [];

  for (const [pid, proj] of Object.entries(projects)) {
    try {
      const existing = await db.execute({
        sql: 'SELECT id, formats, duration, file_size FROM media_items WHERE id = ?',
        args: [pid]
      });

      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        const routing = buildDefaultRouting({ category: proj.category, bunnyLibrary: 'public' });
        let existingFormats = {};
        try { existingFormats = JSON.parse(row.formats || '{}'); } catch (e) { /* keep {} */ }

        // Compute new source values
        const primaryFmtKey = Object.keys(proj.formats)[0] || '16x9';
        const primaryFmt = proj.formats[primaryFmtKey] || {};
        const newDuration = primaryFmt.length || 0;
        const newFileSize = Object.values(proj.formats).reduce((s, f) => s + (f.size || 0), 0);

        const changed =
          formatsChanged(proj.formats, existingFormats) ||
          Math.abs(newDuration - (row.duration || 0)) > 0.5 ||
          newFileSize !== (row.file_size || 0);

        if (changed) {
          // Update source-managed fields ONLY — all editorial fields are untouched
          await db.execute({
            sql: `UPDATE media_items
                  SET formats = ?, duration = ?, file_size = ?,
                      tags = ?, destinations = ?,
                      last_synced_at = datetime('now'), external_updated_at = ?, updated_at = datetime('now')
                  WHERE id = ?`,
            args: [JSON.stringify(proj.formats), newDuration, newFileSize, JSON.stringify(routing.routeTags), JSON.stringify(routing.destinations), proj.dateCreated, pid]
          });
          updated_source++;
          details.push({ id: pid, action: 'updated_source' });
        } else {
          // No source change: only stamp the sync timestamp
          await db.execute({
            sql: `UPDATE media_items SET tags = ?, destinations = ?, last_synced_at = datetime('now') WHERE id = ?`,
            args: [JSON.stringify(routing.routeTags), JSON.stringify(routing.destinations), pid]
          });
          unchanged++;
        }
        continue;
      }

      // ─── New project: insert as published ───
      const primaryFormat = Object.keys(proj.formats)[0] || '16x9';
      const firstFmt = proj.formats[primaryFormat] || {};
      const duration = firstFmt.length || 0;
      const fileSize = Object.values(proj.formats).reduce((sum, f) => sum + (f.size || 0), 0);

      // Compute dedup_key from sorted GUIDs of all formats
      const syncGuids = Object.values(proj.formats).map(f => f && f.guid).filter(Boolean);
      const syncDedupKey = buildDedupKey('video', { guids: syncGuids });
      const syncDupMatch = await checkDuplicate(db, syncDedupKey, pid);

      await db.execute({
        sql: `INSERT INTO media_items
                (id, type, title, status, category, primary_format, formats, bunny_library, source_type,
                 duration, file_size, dedup_key, duplicate_of, duplicate_status,
                 tags, destinations,
                 last_synced_at, external_updated_at, updated_at)
              VALUES (?, 'video', ?, 'published', ?, ?, ?, 'public', 'sync', ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)`,
        args: [
          pid, pid, (proj.category || ''), primaryFormat, JSON.stringify(proj.formats), duration, fileSize,
          syncDedupKey, syncDupMatch ? syncDupMatch.id : null, syncDupMatch ? 'duplicate' : null,
          JSON.stringify(buildDefaultRouting({ category: proj.category, bunnyLibrary: 'public' }).routeTags),
          JSON.stringify(buildDefaultRouting({ category: proj.category, bunnyLibrary: 'public' }).destinations),
          proj.dateCreated, proj.dateCreated
        ]
      });
      imported++;
      const importDetail = { id: pid, action: 'imported', formats: Object.keys(proj.formats) };
      if (syncDupMatch) { importDetail.is_duplicate = true; importDetail.existing_id = syncDupMatch.id; importDetail.existing_title = syncDupMatch.title; }
      details.push(importDetail);
    } catch (err) {
      console.error(`[sync-videos] Error processing ${pid}:`, err.message);
      details.push({ id: pid, action: 'error', error: err.message });
    }
  }

  // ─── Private library: sync projects ───
  for (const [pid, proj] of Object.entries(privateProjects)) {
    try {
      const existing = await db.execute({
        sql: 'SELECT id, formats, duration, file_size FROM media_items WHERE id = ?',
        args: [pid]
      });

      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        const routing = buildDefaultRouting({ category: proj.category, bunnyLibrary: 'private' });
        let existingFormats = {};
        try { existingFormats = JSON.parse(row.formats || '{}'); } catch (e) { /* keep {} */ }
        const primaryFmtKey = Object.keys(proj.formats)[0] || '16x9';
        const primaryFmt = proj.formats[primaryFmtKey] || {};
        const newDuration = primaryFmt.length || 0;
        const newFileSize = Object.values(proj.formats).reduce((s, f) => s + (f.size || 0), 0);
        const changed = formatsChanged(proj.formats, existingFormats) ||
          Math.abs(newDuration - (row.duration || 0)) > 0.5 ||
          newFileSize !== (row.file_size || 0);

        if (changed) {
          await db.execute({
            sql: `UPDATE media_items
                  SET formats = ?, duration = ?, file_size = ?,
                      tags = ?, destinations = ?,
                      is_private = 1, is_locked = 1, bunny_library = 'private',
                      last_synced_at = datetime('now'), external_updated_at = ?, updated_at = datetime('now')
                  WHERE id = ?`,
            args: [JSON.stringify(proj.formats), newDuration, newFileSize, JSON.stringify(routing.routeTags), JSON.stringify(routing.destinations), proj.dateCreated, pid]
          });
          updated_source++;
          details.push({ id: pid, action: 'updated_source', library: 'private' });
        } else {
          await db.execute({
            sql: `UPDATE media_items SET tags = ?, destinations = ?, is_private = 1, is_locked = 1, bunny_library = 'private', last_synced_at = datetime('now') WHERE id = ?`,
            args: [JSON.stringify(routing.routeTags), JSON.stringify(routing.destinations), pid]
          });
          unchanged++;
        }
        continue;
      }

      // New private project: insert
      const primaryFormat = Object.keys(proj.formats)[0] || '16x9';
      const firstFmt = proj.formats[primaryFormat] || {};
      const duration = firstFmt.length || 0;
      const fileSize = Object.values(proj.formats).reduce((sum, f) => sum + (f.size || 0), 0);
      const syncGuids = Object.values(proj.formats).map(f => f && f.guid).filter(Boolean);
      const syncDedupKey = buildDedupKey('video', { guids: syncGuids });
      const syncDupMatch = await checkDuplicate(db, syncDedupKey, pid);

      await db.execute({
        sql: `INSERT INTO media_items
                (id, type, title, status, category, primary_format, formats, bunny_library, is_private, is_locked, source_type,
                 duration, file_size, dedup_key, duplicate_of, duplicate_status,
                 tags, destinations,
                 last_synced_at, external_updated_at, updated_at)
              VALUES (?, 'video', ?, 'published', ?, ?, ?, 'private', 1, 1, 'sync', ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)`,
        args: [
          pid, pid, (proj.category || ''), primaryFormat, JSON.stringify(proj.formats), duration, fileSize,
          syncDedupKey, syncDupMatch ? syncDupMatch.id : null, syncDupMatch ? 'duplicate' : null,
          JSON.stringify(buildDefaultRouting({ category: proj.category, bunnyLibrary: 'private' }).routeTags),
          JSON.stringify(buildDefaultRouting({ category: proj.category, bunnyLibrary: 'private' }).destinations),
          proj.dateCreated, proj.dateCreated
        ]
      });
      imported++;
      const privDetail = { id: pid, action: 'imported', formats: Object.keys(proj.formats), library: 'private' };
      if (syncDupMatch) { privDetail.is_duplicate = true; privDetail.existing_id = syncDupMatch.id; }
      details.push(privDetail);
    } catch (err) {
      console.error(`[sync-videos] Error processing private ${pid}:`, err.message);
      details.push({ id: pid, action: 'error', library: 'private', error: err.message });
    }
  }

  // ─── Orphan cleanup: remove DB videos that no longer exist on Bunny ───
  // Public items: check against public Bunny IDs.
  // Private items: only remove if private fetch succeeded (non-empty), check against private IDs.
  const publicBunnyIds = new Set(Object.keys(projects));
  const privateBunnyIds = new Set(Object.keys(privateProjects));
  const dbVideos = await db.execute({
    sql: "SELECT id, bunny_library, category FROM media_items WHERE type = 'video' AND source_type IN ('upload', 'sync', 'monitor')",
    args: []
  });
  for (const row of dbVideos.rows) {
    const lib = row.bunny_library;
    let shouldRemove = false;
    if (lib === 'private') {
      shouldRemove = bunnyPrivateItems.length > 0 && !privateBunnyIds.has(row.id);
    } else {
      shouldRemove = !publicBunnyIds.has(row.id);
    }
    if (shouldRemove) {
      await db.execute({ sql: 'DELETE FROM media_items WHERE id = ?', args: [row.id] });
      removed++;
      details.push({ id: row.id, action: 'removed', library: lib || 'public' });
    }
  }

  const totalBunny = bunnyItems.length + bunnyPrivateItems.length;
  const totalProjects = Object.keys(projects).length + Object.keys(privateProjects).length;
  console.log(`[sync-videos] bunny=${totalBunny} projects=${totalProjects} imported=${imported} updated_source=${updated_source} unchanged=${unchanged} removed=${removed}`);
  res.status(200).json({
    bunny_items: totalBunny,
    bunny_projects: totalProjects,
    imported,
    updated_source,
    unchanged,
    removed,
    sync_debug: {
      public: {
        ...(publicFetchDebug || {}),
        items_count: bunnyItems.length,
        projects_count: Object.keys(projects).length
      },
      private: {
        ...(privateFetchDebug || {}),
        items_count: bunnyPrivateItems.length,
        projects_count: Object.keys(privateProjects).length
      }
    },
    details
  });
}

async function actionAutoMetadata(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const force = !!(req.body && req.body.force);

  function normalizeFamilySeed(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const stripped = raw
      .replace(/\.[a-z0-9]{2,4}$/i, '')
      .replace(/\((9x16|16x9|1x1)\)/ig, '')
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const withoutRole = stripped
      .replace(/\b(preview-ever|preview|full-movie|short-video|feature|archive)\b\s*$/i, '')
      .replace(/\s+/g, ' ')
      .trim();

    return withoutRole || stripped;
  }

  function toTitleCase(value) {
    return String(value || '')
      .split(' ')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
      .join(' ')
      .trim();
  }

  function categorySuffix(category) {
    const c = String(category || '').trim().toLowerCase();
    if (c === 'preview-ever') return 'Preview Ever';
    if (c === 'preview') return 'Preview';
    if (c === 'full-movie') return 'Film complet';
    if (c === 'short-video') return 'Extrait court';
    if (c === 'feature') return 'Feature';
    if (c === 'archive') return 'Archive';
    return '';
  }

  function categoryDescription(category, familyTitle) {
    const c = String(category || '').trim().toLowerCase();
    if (c === 'preview-ever') return `Preview publique de la famille ${familyTitle}.`;
    if (c === 'preview') return `Preview privee de la famille ${familyTitle}.`;
    if (c === 'full-movie') return `Version complete de la famille ${familyTitle}.`;
    if (c === 'short-video') return `Extrait court de la famille ${familyTitle}.`;
    if (c === 'feature') return `Feature de la famille ${familyTitle}.`;
    if (c === 'archive') return `Element archive de la famille ${familyTitle}.`;
    return `Video de la famille ${familyTitle}.`;
  }

  function mergeTags(existingTags, newTag) {
    const seen = new Set();
    const out = [];
    for (const t of (existingTags || [])) {
      const clean = String(t || '').trim();
      if (!clean) continue;
      const key = clean.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(clean);
    }
    const add = String(newTag || '').trim();
    if (add) {
      const k = add.toLowerCase();
      if (!seen.has(k)) out.push(add);
    }
    return out;
  }

  function shouldRewriteTitle(title) {
    const raw = String(title || '').trim();
    if (!raw) return true;
    if (!/[\s]/.test(raw) && /[-_]/.test(raw)) return true;
    if (/^[a-z0-9._()\-]+$/i.test(raw) && /[-_]/.test(raw)) return true;
    return false;
  }

  const rows = await db.execute({
    sql: "SELECT id, title, description, category, tags FROM media_items WHERE type = 'video'",
    args: []
  });

  let updated = 0;
  let unchanged = 0;
  const details = [];

  for (const row of rows.rows) {
    const familySeed = normalizeFamilySeed(row.family_slug || row.title || row.id);
    const familyTitle = toTitleCase(familySeed || row.id);
    const suffix = categorySuffix(row.category);
    const suggestedTitle = suffix ? `${familyTitle} - ${suffix}` : familyTitle;
    const suggestedDescription = categoryDescription(row.category, familyTitle);
    const familyTag = `family:${slugify(familySeed || row.id)}`;

    let tags = [];
    try { tags = JSON.parse(row.tags || '[]'); } catch (e) { tags = []; }
    const mergedTags = mergeTags(tags, familyTag);

    const nextTitle = (force || shouldRewriteTitle(row.title)) ? suggestedTitle : (row.title || suggestedTitle);
    const nextDescription = (force || !String(row.description || '').trim()) ? suggestedDescription : String(row.description || '');
    const nextTagsStr = JSON.stringify(mergedTags);

    const changed =
      String(row.title || '') !== String(nextTitle || '') ||
      String(row.description || '') !== String(nextDescription || '') ||
      String(row.tags || '[]') !== nextTagsStr;

    if (!changed) {
      unchanged++;
      continue;
    }

    await db.execute({
      sql: `UPDATE media_items
            SET title = ?, description = ?, tags = ?, updated_at = datetime('now')
            WHERE id = ?`,
      args: [nextTitle, nextDescription, nextTagsStr, row.id]
    });

    updated++;
    details.push({ id: row.id, title: nextTitle, family_tag: familyTag });
  }

  return res.status(200).json({ scanned: rows.rows.length, updated, unchanged, force, details: details.slice(0, 20) });
}

async function actionLifecycleBatch(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const body = req.body || {};
  const fromStage = normalizeLifecycleStage(body.from_stage || '');
  const toStage = normalizeLifecycleStage(body.to_stage || '');
  const dryRun = !!body.dry_run;
  const rawIds = Array.isArray(body.ids) ? body.ids : [];
  const ids = rawIds.map(v => String(v || '').trim()).filter(Boolean);

  if (!toStage || !VALID_LIFECYCLE_STAGES.has(toStage)) {
    return res.status(400).json({
      error: 'Invalid to_stage',
      allowed: Array.from(VALID_LIFECYCLE_STAGES)
    });
  }

  if (fromStage && !VALID_LIFECYCLE_STAGES.has(fromStage)) {
    return res.status(400).json({
      error: 'Invalid from_stage',
      allowed: Array.from(VALID_LIFECYCLE_STAGES)
    });
  }

  const where = ["type = 'video'"];
  const args = [];

  if (fromStage) {
    where.push('lifecycle_stage = ?');
    args.push(fromStage);
  }

  if (ids.length > 0) {
    where.push(`id IN (${ids.map(() => '?').join(',')})`);
    args.push(...ids);
  }

  const whereSql = where.join(' AND ');

  const preview = await db.execute({
    sql: `SELECT id, title, lifecycle_stage FROM media_items WHERE ${whereSql} ORDER BY updated_at DESC LIMIT 20`,
    args
  });

  const countRes = await db.execute({
    sql: `SELECT COUNT(*) as cnt FROM media_items WHERE ${whereSql}`,
    args
  });
  const matched = Number(countRes.rows?.[0]?.cnt || 0);

  if (dryRun) {
    return res.status(200).json({
      dry_run: true,
      from_stage: fromStage || null,
      to_stage: toStage,
      matched,
      sample: preview.rows
    });
  }

  const upd = await db.execute({
    sql: `UPDATE media_items
          SET lifecycle_stage = ?, updated_at = datetime('now')
          WHERE ${whereSql}`,
    args: [toStage, ...args]
  });

  return res.status(200).json({
    dry_run: false,
    from_stage: fromStage || null,
    to_stage: toStage,
    matched,
    updated: Number(upd.rowsAffected || 0),
    sample: preview.rows
  });
}

async function actionQualitySummary(req, res, db) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const result = await db.execute({
    sql: `SELECT id, type, title, category, source_url, family_slug, pricing_mode, lifecycle_stage
          FROM media_items
          WHERE type = 'video'
          ORDER BY updated_at DESC`,
    args: []
  });

  const stats = {
    total_items: result.rows.length,
    items_with_warnings: 0,
    by_level: { warn: 0, info: 0 },
    by_code: {}
  };
  const examples = [];

  for (const row of result.rows) {
    const warnings = buildValidationWarnings(row).filter(w => String(w.level || '').toLowerCase() === 'warn');
    if (!warnings.length) continue;

    stats.items_with_warnings++;
    if (examples.length < 15) {
      examples.push({
        id: row.id,
        title: row.title || row.id,
        category: row.category || '',
        warnings
      });
    }

    for (const w of warnings) {
      const level = String(w.level || 'info').toLowerCase();
      if (level === 'warn') stats.by_level.warn++;
      else stats.by_level.info++;

      const code = String(w.code || 'unknown');
      stats.by_code[code] = (stats.by_code[code] || 0) + 1;
    }
  }

  return res.status(200).json({
    ...stats,
    examples
  });
}

// ─── Analytics ───
async function actionAnalytics(req, res, db) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  // Fetch all items once to compute stats client-side
  const allResult = await db.execute({ sql: 'SELECT * FROM media_items', args: [] });
  const items = allResult.rows.map(parseRow);

  // Totals by type
  const totals = {
    videos: items.filter(i => i.type === 'video').length,
    photos: items.filter(i => i.type === 'photo').length
  };
  totals.total = totals.videos + totals.photos;

  // By status
  const by_status = {
    draft: items.filter(i => i.status === 'draft').length,
    ready: items.filter(i => i.status === 'ready').length,
    published: items.filter(i => i.status === 'published').length
  };

  // By source type
  const by_source = {
    upload: items.filter(i => i.source_type === 'upload').length,
    sync: items.filter(i => ['sync', 'monitor'].includes(i.source_type)).length,
    link: items.filter(i => i.source_type === 'link').length
  };

  // By visibility
  const by_visibility = {
    private: items.filter(i => i.is_private).length,
    public: items.filter(i => !i.is_private).length
  };

  // Storage totals
  const totalBytes = items.reduce((sum, i) => sum + (i.file_size || 0), 0);
  const totalDuration = items.reduce((sum, i) => sum + (i.duration || 0), 0);

  // Categories distribution
  const catMap = {};
  items.forEach(i => {
    if (i.category) catMap[i.category] = (catMap[i.category] || 0) + 1;
  });
  const categories = Object.entries(catMap)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  // Recent uploads (last 30 days)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const recentMap = {};
  items.forEach(i => {
    if (i.date_uploaded && i.date_uploaded >= thirtyDaysAgo) {
      const day = i.date_uploaded.substring(0, 10);
      const key = `${day}|${i.type}`;
      recentMap[key] = (recentMap[key] || 0) + 1;
    }
  });
  const recent_uploads = Object.entries(recentMap)
    .map(([key, count]) => {
      const [date, type] = key.split('|');
      return { date, type, count };
    })
    .sort((a, b) => a.date.localeCompare(b.date));

  res.status(200).json({
    totals,
    by_status,
    by_source,
    by_visibility,
    storage: {
      total_bytes: totalBytes,
      total_gb: Math.round((totalBytes / (1024 ** 3)) * 100) / 100,
      total_duration_seconds: totalDuration,
      total_duration_hours: Math.round((totalDuration / 3600) * 100) / 100
    },
    categories,
    recent_uploads
  });
}

// ─── Duplicate management ───

async function actionFindDuplicates(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  // Backfill missing dedup keys so older rows become detectable by duplicate scan.
  const keySeedResult = await db.execute({
    sql: 'SELECT id, type, source_url, storage_path, formats, dedup_key FROM media_items ORDER BY date_uploaded ASC',
    args: []
  });

  let dedup_keys_backfilled = 0;
  for (const row of keySeedResult.rows) {
    let computedKey = null;

    if (row.type === 'video') {
      let formats = {};
      try { formats = JSON.parse(row.formats || '{}'); } catch (e) { formats = {}; }
      const guids = Object.values(formats).map(f => f && f.guid).filter(Boolean);
      computedKey = buildDedupKey('video', { guids });
    }

    if (!computedKey && row.storage_path) {
      computedKey = buildDedupKey('photo', { storagePath: row.storage_path });
    }

    if (!computedKey && row.source_url) {
      computedKey = buildDedupKey('link', { sourceUrl: row.source_url });
    }

    if (computedKey && computedKey !== row.dedup_key) {
      await db.execute({
        sql: "UPDATE media_items SET dedup_key = ?, updated_at = datetime('now') WHERE id = ?",
        args: [computedKey, row.id]
      });
      dedup_keys_backfilled++;
    }
  }

  // Fetch all items that have a dedup_key, ordered oldest first so the original is first in each group.
  const result = await db.execute({
    sql: 'SELECT id, title, type, dedup_key, duplicate_status, date_uploaded FROM media_items WHERE dedup_key IS NOT NULL ORDER BY date_uploaded ASC',
    args: []
  });

  // Group by dedup_key
  const groups = {};
  for (const row of result.rows) {
    const key = row.dedup_key;
    if (!groups[key]) groups[key] = [];
    groups[key].push(row);
  }

  let marked = 0;
  let already_reviewed = 0;
  let groups_found = 0;
  const touchedIds = new Set();

  for (const group of Object.values(groups)) {
    if (group.length <= 1) continue;
    already_reviewed += group.slice(1).filter(i => i.duplicate_status === 'reviewed').length;

    const actionable = group.filter(i => i.duplicate_status !== 'reviewed');
    if (actionable.length <= 1) continue;

    groups_found++;
    const master = actionable[0];
    touchedIds.add(master.id);

    // Ensure the master is marked 'original' unless already reviewed
    if (master.duplicate_status !== 'reviewed') {
      await db.execute({
        sql: "UPDATE media_items SET duplicate_status = 'original' WHERE id = ?",
        args: [master.id]
      });
    }

    for (const dup of actionable.slice(1)) {
      // Mark as duplicate, pointing to master
      await db.execute({
        sql: "UPDATE media_items SET duplicate_status = 'duplicate', duplicate_of = ? WHERE id = ?",
        args: [master.id, dup.id]
      });
      touchedIds.add(dup.id);
      marked++;
    }
  }

  // Clear stale auto flags for items no longer part of duplicate groups.
  // Keep user-reviewed rows untouched.
  let cleared = 0;
  if (touchedIds.size > 0) {
    const placeholders = Array.from({ length: touchedIds.size }).map(() => '?').join(',');
    const clearRes = await db.execute({
      sql: `UPDATE media_items
            SET duplicate_status = NULL, duplicate_of = NULL
            WHERE duplicate_status IN ('original', 'duplicate')
              AND id NOT IN (${placeholders})`,
      args: Array.from(touchedIds)
    });
    cleared = clearRes.rowsAffected || 0;
  } else {
    const clearRes = await db.execute({
      sql: `UPDATE media_items
            SET duplicate_status = NULL, duplicate_of = NULL
            WHERE duplicate_status IN ('original', 'duplicate')`,
      args: []
    });
    cleared = clearRes.rowsAffected || 0;
  }

  console.log(`[find-duplicates] groups=${groups_found} marked=${marked} already_reviewed=${already_reviewed} dedup_keys_backfilled=${dedup_keys_backfilled} cleared=${cleared}`);
  res.status(200).json({ groups_found, marked, already_reviewed, dedup_keys_backfilled, cleared });
}

async function actionResolveDuplicate(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { id, action, delete_cdn } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id required' });
  if (!['mark-not-duplicate', 'delete'].includes(action)) {
    return res.status(400).json({ error: 'action must be mark-not-duplicate or delete' });
  }

  const existing = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (existing.rows.length === 0) return res.status(404).json({ error: 'Not found' });

  if (action === 'mark-not-duplicate') {
    await db.execute({
      sql: "UPDATE media_items SET duplicate_status = 'reviewed', duplicate_of = NULL WHERE id = ?",
      args: [id]
    });
    return res.status(200).json({ resolved: true, id, action });
  }

  // action === 'delete': remove from DB (and optionally from CDN)
  const item = parseRow(existing.rows[0]);
  const cdnResults = [];

  if (delete_cdn) {
    if (item.type === 'video') {
      const lib = item.bunny_library === 'private' ? PRIVATE : PUBLIC;
      for (const [, fmtData] of Object.entries(item.formats || {})) {
        const guid = fmtData && fmtData.guid;
        if (!guid) continue;
        try {
          const delRes = await httpsRequest({
            hostname: 'video.bunnycdn.com',
            path: `/library/${lib.id}/videos/${guid}`,
            method: 'DELETE',
            headers: { 'AccessKey': lib.key }
          }, null);
          cdnResults.push({ guid, status: delRes.status });
        } catch (e) {
          cdnResults.push({ guid, error: e.message });
        }
      }
    } else if (item.type === 'photo' && item.storage_path) {
      try {
        const delRes = await httpsRequest({
          hostname: 'ny.storage.bunnycdn.com',
          path: `/${STORAGE.name}${item.storage_path}`,
          method: 'DELETE',
          headers: { 'AccessKey': STORAGE.password }
        }, null);
        cdnResults.push({ path: item.storage_path, status: delRes.status });
      } catch (e) {
        cdnResults.push({ path: item.storage_path, error: e.message });
      }
    }
  }

  await db.execute({ sql: 'DELETE FROM media_items WHERE id = ?', args: [id] });
  console.log(`[resolve-duplicate] deleted id=${id} cdn=${delete_cdn}`);
  res.status(200).json({ resolved: true, id, action, cdn_results: cdnResults });
}

// ─── Router ───
const ACTIONS = {
  auth: actionAuth,
  list: actionList,
  'env-health': actionEnvHealth,
  update: actionUpdate,
  delete: actionDelete,
  'tag-boxes': actionTagBoxes,
  'save-tag-box': actionSaveTagBox,
  'delete-tag-box': actionDeleteTagBox,
  'import-link': actionImportLink,
  upload: actionUpload,
  'sync-videos': actionSyncVideos,
  'quality-summary': actionQualitySummary,
  analytics: actionAnalytics,
  'resolve-duplicate': actionResolveDuplicate,
};

// Explicitly retained but disabled from routing.
const DISABLED_ACTIONS = [
  actionMigrateShowcase,
  actionSyncPhotos,
  actionAutoMetadata,
  actionLifecycleBatch,
  actionFindDuplicates,
];
void DISABLED_ACTIONS;

module.exports = async (req, res) => {
  corsHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = getQuery(req).action;
  if (action === 'by-destination') {
    return res.status(410).json({
      error: 'Action moved',
      message: 'Use /api/consumer-read?dest=... with ADMIN_SERVICE_KEY',
    });
  }
  const handler = ACTIONS[action];
  if (!handler) {
    return res.status(400).json({ error: `Unknown action: ${action}`, available: Object.keys(ACTIONS) });
  }

  if (action !== 'auth' && !isAuthorizedRequest(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (ENV_STRICT_MODE && action !== 'env-health' && action !== 'auth') {
    const strict = getStrictBlockingMissing(action, req);
    if (strict.missing.length > 0) {
      return res.status(503).json({
        error: 'ENV_STRICT_MODE blocking request: missing environment variables',
        action,
        missing: strict.missing,
      });
    }
  }

  try {
    const t0 = Date.now();
    await ensureTable();
    const db = getDb();
    await handler(req, res, db);
    console.log(`[admin-api] action=${action} ${Date.now() - t0}ms`);
  } catch (error) {
    console.error(`admin-api [${action}] error:`, error);
    res.status(500).json({ error: error.message });
  }
};
