const crypto = require('crypto');
const { ensureTable, getDb, corsHeaders, parseRow } = require('./_admin-db');

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

function normalizeRouteTag(tag) {
  const raw = String(tag || '').trim().toLowerCase();
  if (!raw) return '';
  if (!raw.startsWith(ROUTE_TAG_PREFIX)) return '';
  return raw.replace(/[^a-z0-9:-]/g, '');
}

function isRouteTag(tag) {
  return String(tag || '').toLowerCase().startsWith(ROUTE_TAG_PREFIX);
}

function destinationFromRouteTag(tag) {
  const norm = normalizeRouteTag(tag);
  if (!norm) return '';
  const route = norm.slice(ROUTE_TAG_PREFIX.length);
  if (route === 'catalog' || route === 'main-site') return route;
  if (route.startsWith('project:')) return route;
  return '';
}

function buildRouteTags({ tags, destinations }) {
  const out = new Set();

  for (const tag of parseArraySafe(tags)) {
    const norm = normalizeRouteTag(tag);
    if (norm) out.add(norm);
  }

  for (const dest of parseArraySafe(destinations)) {
    const raw = String(dest || '').trim().toLowerCase();
    if (!raw) continue;
    const rt = normalizeRouteTag(`${ROUTE_TAG_PREFIX}${raw}`);
    if (rt) out.add(rt);
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
  const routeTags = buildRouteTags({ tags: item.tags, destinations: item.destinations });
  const destinations = [...new Set([
    ...parseArraySafe(item.destinations),
    ...buildDestinationsFromRouteTags(routeTags),
  ])];

  const contentTags = parseArraySafe(item.tags).filter(tag => !isRouteTag(tag));

  return {
    ...item,
    tags: [...new Set([...contentTags, ...routeTags])],
    destinations,
    route_tags: routeTags,
  };
}

function normalizePullZone(value, fallback) {
  const raw = String(value || '').trim();
  if (!raw) return fallback;
  if (/^https?:\/\//i.test(raw)) return raw.replace(/\/$/, '');
  return `https://${raw.replace(/^\/+/, '').replace(/\/$/, '')}`;
}

const PRIVATE = {
  id: String(process.env.BUNNY_PRIVATE_LIBRARY_ID || '').trim(),
  pull: normalizePullZone(process.env.BUNNY_PRIVATE_PULL_ZONE, ''),
};

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
  } catch (_err) {
    return url;
  }
}

function buildEmbedUrl(libraryId, guid, signingKey, expirationSeconds = 3600) {
  if (!libraryId || !guid) return '';

  const base = `https://iframe.mediadelivery.net/embed/${libraryId}/${guid}`;
  if (!signingKey) return base;

  try {
    const expires = Math.floor(Date.now() / 1000) + expirationSeconds;
    const payload = `${signingKey}${guid}${expires}`;
    const token = crypto.createHash('sha256').update(payload).digest('hex');
    return `${base}?token=${token}&expires=${expires}`;
  } catch (_err) {
    return base;
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

  const cdnSigningKey = (process.env.BUNNY_TOKEN_KEY || process.env.BUNNY_PRIVATE_ACCESS_KEY || '').trim();
  const embedSigningKey = (process.env.BUNNY_EMBED_TOKEN_KEY || process.env.BUNNY_TOKEN_KEY || '').trim();

  const formats = item.formats || {};
  const signedFormats = {};

  for (const [fmt, data] of Object.entries(formats)) {
    if (!data) continue;

    const bunnyUrl = normalizeBunnyAssetUrl(data.bunny_url, PRIVATE.pull, data.guid, 'play_720p.mp4');
    const thumbnailUrl = normalizeBunnyAssetUrl(data.thumbnail_url, PRIVATE.pull, data.guid, 'thumbnail.jpg');
    const guid = String(data.guid || '').trim();
    const embedUrl = buildEmbedUrl(PRIVATE.id, guid, embedSigningKey, 3600);

    signedFormats[fmt] = {
      ...data,
      bunny_url: bunnyUrl ? signUrl(bunnyUrl, cdnSigningKey, 3600) : bunnyUrl,
      thumbnail_url: thumbnailUrl ? signUrl(thumbnailUrl, cdnSigningKey, 86400) : thumbnailUrl,
      embed_url: embedUrl || data.embed_url || '',
    };
  }

  return {
    ...item,
    formats: signedFormats,
  };
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

function checkServiceAuth(req) {
  const serviceKey = (process.env.ADMIN_SERVICE_KEY || '').trim();
  if (!serviceKey) return { ok: false, status: 503, error: 'ADMIN_SERVICE_KEY not configured on server' };

  const auth = String(req.headers?.authorization || '').trim();
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || parts[1].trim() !== serviceKey) {
    return { ok: false, status: 401, error: 'Unauthorized' };
  }
  return { ok: true };
}

module.exports = async (req, res) => {
  corsHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const auth = checkServiceAuth(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

  const { dest } = getQuery(req);
  if (!dest) return res.status(400).json({ error: 'Missing ?dest= parameter' });

  try {
    await ensureTable();
    const db = getDb();

    const safeDest = String(dest).replace(/[%_\\]/g, c => `\\${c}`);
    const routeTag = normalizeRouteTag(`${ROUTE_TAG_PREFIX}${dest}`);
    const safeRouteTag = routeTag.replace(/[%_\\]/g, c => `\\${c}`);

    const result = await db.execute({
      sql: `SELECT * FROM media_items
            WHERE status = 'published'
              AND ((tags LIKE ? ESCAPE '\\') OR (destinations LIKE ? ESCAPE '\\'))
              AND (duplicate_status IS NULL OR duplicate_status != 'duplicate')
            ORDER BY date_filmed DESC, date_uploaded DESC`,
      args: [`%"${safeRouteTag}"%`, `%"${safeDest}"%`],
    });

    const items = result.rows.map(parseRow).map(withRouteFields).map(signPrivateMediaItem);
    return res.status(200).json({ dest, count: items.length, items });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'consumer-read failed' });
  }
};
