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

// ─── Bunny Config ───
const PUBLIC = {
  id: process.env.BUNNY_LIBRARY_ID || '581630',
  key: process.env.BUNNY_ACCESS_KEY || '',
  pull: normalizePullZone(process.env.BUNNY_PULL_ZONE, 'https://vz-72668a20-6b9.b-cdn.net')
};
const PUBLIC_SYNC_COLLECTION_ID = (process.env.BUNNY_PUBLIC_SYNC_COLLECTION_ID || '').trim();
const PUBLIC_SYNC_CATEGORY = (process.env.BUNNY_PUBLIC_SYNC_CATEGORY || 'preview-ever').trim();
const PUBLIC_SYNC_COLLECTIONS = [
  { category: 'preview-ever', id: (process.env.BUNNY_PUBLIC_PREVIEW_EVER_COLLECTION_ID || PUBLIC_SYNC_COLLECTION_ID || '').trim() },
  { category: 'archive', id: (process.env.BUNNY_PUBLIC_ARCHIVE_COLLECTION_ID || '').trim() },
  { category: 'feature', id: (process.env.BUNNY_PUBLIC_FEATURE_COLLECTION_ID || '').trim() }
].filter(c => c.category && c.id);
const EXTERNAL_CATALOG_PREVIEWS_URL = (process.env.EXTERNAL_CATALOG_PREVIEWS_URL || '').trim();
const EXTERNAL_CATALOG_MOVIES_URL = (process.env.EXTERNAL_CATALOG_MOVIES_URL || '').trim();
const EXTERNAL_CATALOG_SYNC_CATEGORY = (process.env.EXTERNAL_CATALOG_SYNC_CATEGORY || PUBLIC_SYNC_CATEGORY || 'preview-ever').trim();
const ENABLE_EXTERNAL_CATALOG_SYNC = String(process.env.ENABLE_EXTERNAL_CATALOG_SYNC || '').trim().toLowerCase() === 'true';
const EXTERNAL_CATALOG_PRIVATE_COLLECTION_CATEGORIES = new Set(['preview', 'full-movie', 'short-video']);
const PRIVATE = {
  id: process.env.BUNNY_PRIVATE_LIBRARY_ID || '552081',
  key: process.env.BUNNY_PRIVATE_ACCESS_KEY || '',
  pull: normalizePullZone(process.env.BUNNY_PRIVATE_PULL_ZONE, 'https://vz-c69f4e3f-963.b-cdn.net')
};
const PRIVATE_SYNC_COLLECTION_ID = (process.env.BUNNY_PRIVATE_SYNC_COLLECTION_ID || '').trim();
const PRIVATE_SYNC_CATEGORY = (process.env.BUNNY_PRIVATE_SYNC_CATEGORY || 'preview').trim();
const PRIVATE_SYNC_COLLECTIONS = [
  { category: 'preview', id: (process.env.BUNNY_PRIVATE_PREVIEW_COLLECTION_ID || PRIVATE_SYNC_COLLECTION_ID || '').trim() },
  { category: 'full-movie', id: (process.env.BUNNY_PRIVATE_FULL_MOVIE_COLLECTION_ID || '').trim() },
  { category: 'short-video', id: (process.env.BUNNY_PRIVATE_SHORT_VIDEO_COLLECTION_ID || '').trim() }
].filter(c => c.category && c.id);
const STORAGE = {
  name: process.env.BUNNY_STORAGE_NAME || '',
  password: process.env.BUNNY_STORAGE_PASSWORD || '',
  pullZone: normalizePullZone(process.env.BUNNY_STORAGE_PULL_ZONE, '')
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

const PREVIEW_CATEGORIES = new Set(['preview', 'preview-ever', 'short-video']);
const FULL_CATEGORIES = new Set(['full-movie']);
const VALID_PRICING_MODES = new Set(['a-la-carte', 'subscription', 'both']);
const VALID_LIFECYCLE_STAGES = new Set(['feature', 'preview-ever', 'archive']);

function buildValidationWarnings(item) {
  const warnings = [];
  const type = String(item.type || '').toLowerCase();
  const category = String(item.category || '').trim().toLowerCase();
  const sourceUrl = String(item.source_url || '').trim();
  const familySlug = String(item.family_slug || '').trim();
  const pricingMode = normalizePricingMode(item.pricing_mode || '');
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

  if (FULL_CATEGORIES.has(category) && !pricingMode) {
    warnings.push({
      level: 'warn',
      code: 'missing_pricing_mode',
      message: 'Full-movie sans pricing_mode (a-la-carte, subscription, both).'
    });
  }

  if (pricingMode && !VALID_PRICING_MODES.has(pricingMode)) {
    warnings.push({
      level: 'warn',
      code: 'invalid_pricing_mode',
      message: 'pricing_mode invalide. Valeurs: a-la-carte, subscription, both.'
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

function normalizeCollectionId(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  // Accept plain UUID or path-like values such as "collection/name/<uuid>".
  const m = raw.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return m ? m[0] : raw;
}

function parseBunnyItemsPayload(data) {
  const parsed = JSON.parse(data || '{}');
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.items)) return parsed.items;
  return [];
}

async function fetchBunnyVideos({ libraryId, accessKey, collectionId = '' }) {
  const headers = { 'AccessKey': accessKey, 'accept': 'application/json' };
  const cleanCollectionId = normalizeCollectionId(collectionId);

  if (cleanCollectionId) {
    const paths = [
      `/library/${libraryId}/collections/${encodeURIComponent(cleanCollectionId)}/videos?itemsPerPage=1000&orderBy=date`,
      `/library/${libraryId}/videos?itemsPerPage=1000&orderBy=date&collection=${encodeURIComponent(cleanCollectionId)}`
    ];

    for (const p of paths) {
      const r = await httpsRequest({ hostname: 'video.bunnycdn.com', path: p, method: 'GET', headers });
      if (r.status === 200) {
        return {
          items: parseBunnyItemsPayload(r.data),
          debug: {
            collection_requested: String(collectionId || ''),
            collection_normalized: cleanCollectionId,
            endpoint_used: p,
            status: r.status
          }
        };
      }
    }
    throw new Error(`Bunny collection fetch failed for ${cleanCollectionId}`);
  }

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
      collection_requested: String(collectionId || ''),
      collection_normalized: '',
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

  const signingKey = (process.env.BUNNY_TOKEN_KEY || process.env.BUNNY_PRIVATE_ACCESS_KEY || '').trim();
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
  const items = result.rows.map(parseRow).map(withValidation).map(signPrivateMediaItem);
  res.status(200).json(items);
}

/**
 * Fire-and-forget: notifie les plateformes consommatrices quand un item est sauvegardé.
 * - project routes: invalide le cache via POST /api/revalidate?slug=X
 * - catalog route: déclenche un sync via POST /api/webhook/sync
 * Ne bloque jamais l'appelant (erreurs loguées silencieusement).
 */
function notifyDestinations(destinations) {
  const dests = Array.isArray(destinations) ? destinations : [];
  if (dests.length === 0) return;

  const projectRoutesUrl = (process.env.PROJECT_ROUTES_URL || '').trim().replace(/\/$/, '');
  const revalidateSecret = (process.env.PROJECT_ROUTES_REVALIDATE_SECRET || '').trim();
  const catalogSyncUrl = (process.env.CATALOG_SYNC_URL || '').trim().replace(/\/$/, '');
  const catalogWebhookSecret = (process.env.CATALOG_SYNC_WEBHOOK_SECRET || '').trim();

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

  if (catalogSyncUrl && catalogWebhookSecret && dests.includes('catalog')) {
    fetch(`${catalogSyncUrl}/api/webhook/sync`, {
      method: 'POST',
      headers: { 'x-webhook-secret': catalogWebhookSecret },
    }).catch(e => console.error('[notify] catalog webhook failed:', e.message));
  }
}

async function actionUpdate(req, res, db) {
  if (req.method !== 'PATCH' && req.method !== 'PUT') return res.status(405).json({ error: 'PATCH or PUT only' });

  const { id } = getQuery(req);
  if (!id) return res.status(400).json({ error: 'Missing ?id= parameter' });

  const body = req.body;
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

  for (const key of ['tags', 'formats', 'social_meta', 'destinations']) {
    if (body[key] !== undefined) { fields.push(`${key} = ?`); values.push(JSON.stringify(body[key])); }
  }

  if (body.status !== undefined) { fields.push('status = ?'); values.push(body.status); }
  fields.push("updated_at = datetime('now')");
  values.push(id);

  await db.execute({ sql: `UPDATE media_items SET ${fields.join(', ')} WHERE id = ?`, args: values });

  const result = await db.execute({ sql: 'SELECT * FROM media_items WHERE id = ?', args: [id] });
  if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  const updatedItem = withValidation(parseRow(result.rows[0]));
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
  const type = body.type || 'video';
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
  const destinations = Array.isArray(body.destinations) ? body.destinations : [];

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
            VALUES (?, 'video', ?, ?, ?, ?, ?, ?, ?, 'published', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      args: [
        id, title, body.description || '',
        JSON.stringify(body.tags || []), body.category || '',
        body.date_filmed || null,
        isPrivate ? 1 : 0, isPrivate ? 1 : 0,
        format, JSON.stringify(formats),
        body.source_type || 'upload', body.source_url || '', body.notes || '', familySlug,
        isPrivate ? 'private' : 'public',
        pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
        dedupKey, duplicateOf, duplicateStatus, JSON.stringify(destinations)
      ]
    });

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
            VALUES (?, 'photo', ?, ?, ?, ?, ?, 0, 0, 'published', 'upload', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        args: [
          id, title, body.description || '',
          JSON.stringify(body.tags || []), body.category || '',
          body.date_filmed || null,
          photoStoragePath, buffer.length, body.notes || '', familySlug,
            pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
          photoDedupKey,
          photoDupMatch ? photoDupMatch.id : null,
          photoDupMatch ? 'duplicate' : null,
          JSON.stringify(destinations)
        ]
      });
      result.url = url;
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
            VALUES (?, 'photo', ?, ?, ?, ?, ?, 'published', 'link', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        args: [
          id, title, body.description || '',
          JSON.stringify(body.tags || []), body.category || '',
          body.date_filmed || null,
          body.source_url || '', body.notes || '', familySlug,
            pricingMode, lifecycleStage, ctaLabel, qualityLevel, sortOrder, isFeatured ? 1 : 0,
          linkDedupKey,
          linkDupMatch ? linkDupMatch.id : null,
          linkDupMatch ? 'duplicate' : null,
          JSON.stringify(destinations)
        ]
      });
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

  // ─── Fetch all videos from Bunny Stream (public + private) ───
  let bunnyItems = [];
  let publicFetchDebug = { collections: [] };
  try {
    if (PUBLIC_SYNC_COLLECTIONS.length > 0) {
      for (const c of PUBLIC_SYNC_COLLECTIONS) {
        const publicFetch = await fetchBunnyVideos({
          libraryId: PUBLIC.id,
          accessKey: PUBLIC.key,
          collectionId: c.id
        });
        const taggedItems = (publicFetch.items || []).map(item => ({
          ...item,
          __syncCategory: c.category,
          __syncCollectionId: c.id
        }));
        bunnyItems.push(...taggedItems);
        publicFetchDebug.collections.push({
          category: c.category,
          collection_id: c.id,
          fetch: publicFetch.debug,
          items_count: taggedItems.length
        });
      }
    } else {
      // Aucune collection configurée → fetch toute la library publique
      const publicFetch = await fetchBunnyVideos({ libraryId: PUBLIC.id, accessKey: PUBLIC.key });
      bunnyItems = (publicFetch.items || []).map(item => ({ ...item, __syncCategory: PUBLIC_SYNC_CATEGORY }));
      publicFetchDebug.collections.push({ category: PUBLIC_SYNC_CATEGORY, collection_id: null, fetch: publicFetch.debug, items_count: bunnyItems.length });
    }

    // Dedup by Bunny guid in case a video appears in multiple collections.
    const byGuid = new Map();
    for (const item of bunnyItems) {
      if (!item || !item.guid) continue;
      if (!byGuid.has(item.guid)) byGuid.set(item.guid, item);
    }
    bunnyItems = Array.from(byGuid.values());
    publicFetchDebug.total_items_after_dedup = bunnyItems.length;
    publicFetchDebug.categories = PUBLIC_SYNC_COLLECTIONS.length > 0 ? PUBLIC_SYNC_COLLECTIONS.map(c => c.category) : [PUBLIC_SYNC_CATEGORY];
  } catch (err) {
    console.error('[sync-videos] Bunny fetch error:', err.message);
    return res.status(502).json({ error: `Bunny fetch failed: ${err.message}` });
  }

  let bunnyPrivateItems = [];
  let privateFetchDebug = { collections: [] };
  try {
    if (PRIVATE_SYNC_COLLECTIONS.length > 0) {
    for (const c of PRIVATE_SYNC_COLLECTIONS) {
      const privateFetch = await fetchBunnyVideos({
        libraryId: PRIVATE.id,
        accessKey: PRIVATE.key,
        collectionId: c.id
      });
      const taggedItems = (privateFetch.items || []).map(item => ({
        ...item,
        __syncCategory: c.category,
        __syncCollectionId: c.id
      }));
      bunnyPrivateItems.push(...taggedItems);
      privateFetchDebug.collections.push({
        category: c.category,
        collection_id: c.id,
        fetch: privateFetch.debug,
        items_count: taggedItems.length
      });
    }

      // Dedup by Bunny guid in case a video appears in multiple collections.
      const byGuid = new Map();
      for (const item of bunnyPrivateItems) {
        if (!item || !item.guid) continue;
        if (!byGuid.has(item.guid)) byGuid.set(item.guid, item);
      }
      bunnyPrivateItems = Array.from(byGuid.values());
      privateFetchDebug.total_items_after_dedup = bunnyPrivateItems.length;
      privateFetchDebug.categories = PRIVATE_SYNC_COLLECTIONS.map(c => c.category);
    } else {
      // Aucune collection configurée → fetch toute la library privée
      const privateFetch = await fetchBunnyVideos({ libraryId: PRIVATE.id, accessKey: PRIVATE.key });
      bunnyPrivateItems = (privateFetch.items || []).map(item => ({ ...item, __syncCategory: PRIVATE_SYNC_CATEGORY }));
      privateFetchDebug.collections.push({ category: PRIVATE_SYNC_CATEGORY, collection_id: null, fetch: privateFetch.debug, items_count: bunnyPrivateItems.length });
      privateFetchDebug.total_items_after_dedup = bunnyPrivateItems.length;
      privateFetchDebug.categories = [PRIVATE_SYNC_CATEGORY];
    }
  } catch (err) {
    console.warn('[sync-videos] Private Bunny fetch (non-fatal):', err.message);
    privateFetchDebug = { endpoint_used: null, status: 'error', error: err.message };
  }

  // ─── Group individual video files into multi-format projects ───
  // Convention: Bunny title "my-video (16x9)" → project "my-video", format "16x9"
  function groupProjects(items, lib) {
    const projs = {};
    for (const v of items) {
      const match = v.title.match(/^(.*) \((.*)\)$/);
      const rawPid = match ? match[1] : v.title.replace(/\.[^/.]+$/, '');
      const pid = rawPid || v.title;
      const fmt = match ? match[2] : '16x9';
      if (!projs[pid]) {
        projs[pid] = {
          id: pid,
          formats: {},
          dateCreated: v.dateCreated,
          category: v.__syncCategory || null,
          collectionId: v.__syncCollectionId || null
        };
      }
      projs[pid].formats[fmt] = {
        bunny_url: `${lib.pull}/${v.guid}/play_720p.mp4`,
        guid: v.guid,
        thumbnail_url: `${lib.pull}/${v.guid}/${v.thumbnailFileName || 'thumbnail.jpg'}`,
        length: v.length, width: v.width, height: v.height, size: v.storageSize
      };
      if (new Date(v.dateCreated) > new Date(projs[pid].dateCreated)) projs[pid].dateCreated = v.dateCreated;
      if (!projs[pid].category && v.__syncCategory) projs[pid].category = v.__syncCategory;
      if (!projs[pid].collectionId && v.__syncCollectionId) projs[pid].collectionId = v.__syncCollectionId;
    }
    return projs;
  }

  const projects = groupProjects(bunnyItems, PUBLIC);
  const privateProjects = groupProjects(bunnyPrivateItems, PRIVATE);

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
                      last_synced_at = datetime('now'), external_updated_at = ?, updated_at = datetime('now')
                  WHERE id = ?`,
            args: [JSON.stringify(proj.formats), newDuration, newFileSize, proj.dateCreated, pid]
          });
          updated_source++;
          details.push({ id: pid, action: 'updated_source' });
        } else {
          // No source change: only stamp the sync timestamp
          await db.execute({
            sql: `UPDATE media_items SET last_synced_at = datetime('now') WHERE id = ?`,
            args: [pid]
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
                 last_synced_at, external_updated_at, updated_at)
              VALUES (?, 'video', ?, 'published', ?, ?, ?, 'public', 'sync', ?, ?, ?, ?, ?, datetime('now'), ?, ?)`,
        args: [
          pid, pid, (proj.category || PUBLIC_SYNC_CATEGORY), primaryFormat, JSON.stringify(proj.formats), duration, fileSize,
          syncDedupKey, syncDupMatch ? syncDupMatch.id : null, syncDupMatch ? 'duplicate' : null,
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
                      is_private = 1, is_locked = 1, bunny_library = 'private',
                      last_synced_at = datetime('now'), external_updated_at = ?, updated_at = datetime('now')
                  WHERE id = ?`,
            args: [JSON.stringify(proj.formats), newDuration, newFileSize, proj.dateCreated, pid]
          });
          updated_source++;
          details.push({ id: pid, action: 'updated_source', library: 'private' });
        } else {
          await db.execute({
            sql: `UPDATE media_items SET is_private = 1, is_locked = 1, bunny_library = 'private', last_synced_at = datetime('now') WHERE id = ?`,
            args: [pid]
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
                 last_synced_at, external_updated_at, updated_at)
              VALUES (?, 'video', ?, 'published', ?, ?, ?, 'private', 1, 1, 'sync', ?, ?, ?, ?, ?, datetime('now'), ?, ?)`,
        args: [
          pid, pid, (proj.category || PRIVATE_SYNC_CATEGORY), primaryFormat, JSON.stringify(proj.formats), duration, fileSize,
          syncDedupKey, syncDupMatch ? syncDupMatch.id : null, syncDupMatch ? 'duplicate' : null,
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
  const publicSyncCategories = new Set(PUBLIC_SYNC_COLLECTIONS.map(c => c.category));
  const privateSyncCategories = new Set(PRIVATE_SYNC_COLLECTIONS.map(c => c.category));
  const dbVideos = await db.execute({
    sql: "SELECT id, bunny_library, category FROM media_items WHERE type = 'video' AND source_type IN ('upload', 'sync', 'monitor')",
    args: []
  });
  for (const row of dbVideos.rows) {
    const lib = row.bunny_library;
    let shouldRemove = false;
    if (lib === 'private') {
      if (PRIVATE_SYNC_COLLECTIONS.length > 0) {
        // Safety: when syncing a private subset by collections, only cleanup rows in those sync categories.
        shouldRemove = privateSyncCategories.has(row.category) && bunnyPrivateItems.length > 0 && !privateBunnyIds.has(row.id);
      } else {
        shouldRemove = bunnyPrivateItems.length > 0 && !privateBunnyIds.has(row.id);
      }
    } else {
      if (PUBLIC_SYNC_COLLECTIONS.length > 0) {
        // Safety: when syncing a public subset by collections, only cleanup rows in those sync categories.
        shouldRemove = publicSyncCategories.has(row.category) && bunnyItems.length > 0 && !publicBunnyIds.has(row.id);
      } else {
        shouldRemove = !publicBunnyIds.has(row.id);
      }
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

async function actionSyncExternalCatalog(req, res, db) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  if (!ENABLE_EXTERNAL_CATALOG_SYNC) {
    return res.status(403).json({
      error: 'sync-external-catalog disabled',
      message: 'Enable ENABLE_EXTERNAL_CATALOG_SYNC=true only for migration/recovery runs.'
    });
  }

  function normalizeExternalCatalogPrivateCategory(value, title) {
    const raw = String(value || '').trim().toLowerCase();
    if (EXTERNAL_CATALOG_PRIVATE_COLLECTION_CATEGORIES.has(raw)) return raw;
    const t = String(title || '').toLowerCase();
    if (raw.includes('preview') || t.includes('preview')) return 'preview';
    if (raw.includes('short') || t.includes('short')) return 'short-video';
    return 'full-movie';
  }

  function extractGuidFromPreviewUrl(url) {
    try {
      const u = new URL(String(url || ''));
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length >= 2) {
        const candidate = parts[0];
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(candidate)) {
          return candidate;
        }
      }
      return '';
    } catch (e) {
      return '';
    }
  }

  let payload;
  let sourceEndpoint = EXTERNAL_CATALOG_PREVIEWS_URL;
  let usedFallback = false;
  try {
    const r = await fetch(EXTERNAL_CATALOG_PREVIEWS_URL, {
      method: 'GET',
      headers: { 'accept': 'application/json' }
    });
    if (!r.ok) {
      return res.status(502).json({ error: `External catalog fetch failed: ${r.status}` });
    }
    payload = await r.json();
  } catch (err) {
    return res.status(502).json({ error: `External catalog fetch failed: ${err.message}` });
  }

  let previews = Array.isArray(payload?.data) ? payload.data : [];
  let filtered_out_library = 0;

  // Fallback: some deployments expose preview URLs only via /api/movies.
  if (previews.length === 0) {
    try {
      const r = await fetch(EXTERNAL_CATALOG_MOVIES_URL, {
        method: 'GET',
        headers: { 'accept': 'application/json' }
      });
      if (r.ok) {
        const moviesPayload = await r.json();
        const movies = Array.isArray(moviesPayload?.data) ? moviesPayload.data : [];
        const privateLibraryMovies = movies.filter(m => String(m?.bunnyLibraryId || '') === String(PRIVATE.id));
        filtered_out_library = Math.max(0, movies.length - privateLibraryMovies.length);
        previews = privateLibraryMovies
          .filter(m => m && m.previewUrl)
          .map(m => ({
            id: m.id || m._id || m.bunnyVideoId,
            title: m.title,
            category: m.category || '',
            thumbnailUrl: m.thumbnailUrl || '',
            previewUrl: m.previewUrl,
            embedUrl: m.embedUrl || ''
          }));
        if (previews.length > 0) {
          sourceEndpoint = EXTERNAL_CATALOG_MOVIES_URL;
          usedFallback = true;
        }
      }
    } catch (err) {
      console.warn('[sync-external-catalog] fallback /api/movies failed:', err.message);
    }
  }

  let imported = 0, updated_source = 0, unchanged = 0;
  const details = [];

  for (const p of previews) {
    const sourceUrl = String(p?.previewUrl || p?.embedUrl || '').trim();
    const thumbUrl = String(p?.thumbnailUrl || '').trim();
    const rawTitle = String(p?.title || '').trim();
    const normalizedCategory = normalizeExternalCatalogPrivateCategory(p?.category, rawTitle);
    const extId = String(p?.id || '').trim();
    const guid = extractGuidFromPreviewUrl(sourceUrl);
    if (!sourceUrl || !rawTitle) continue;

    const id = `catalog-${slugify(extId || rawTitle) || crypto.createHash('sha1').update(sourceUrl).digest('hex').slice(0, 12)}`;
    const formatsObj = {
      '16x9': {
        bunny_url: sourceUrl,
        thumbnail_url: thumbUrl,
        guid,
        source_url: sourceUrl,
        site_name: 'external-catalog',
      }
    };
    const formats = JSON.stringify(formatsObj);
    const dedupKey = guid
      ? buildDedupKey('video', { guids: [guid] })
      : buildDedupKey('link', { sourceUrl });

    const existing = await db.execute({
      sql: 'SELECT id, title, source_url, formats FROM media_items WHERE id = ?',
      args: [id]
    });

    if (existing.rows.length > 0) {
      const row = existing.rows[0];
      const changed =
        String(row.title || '') !== rawTitle ||
        String(row.source_url || '') !== sourceUrl ||
        String(row.formats || '{}') !== formats;

      if (changed) {
        await db.execute({
          sql: `UPDATE media_items
                SET title = ?, source_url = ?, formats = ?, category = ?, status = 'published',
                    source_type = 'sync', bunny_library = 'private', is_private = 1, is_locked = 1,
                    dedup_key = ?,
                    last_synced_at = datetime('now'), updated_at = datetime('now')
                WHERE id = ?`,
          args: [rawTitle, sourceUrl, formats, normalizedCategory, dedupKey, id]
        });
        updated_source++;
        details.push({ id, action: 'updated_source' });
      } else {
        await db.execute({
          sql: `UPDATE media_items
                SET status = 'published', category = ?, source_type = 'sync', bunny_library = 'private', is_private = 1, is_locked = 1,
                    dedup_key = ?, last_synced_at = datetime('now')
                WHERE id = ?`,
          args: [normalizedCategory, dedupKey, id]
        });
        unchanged++;
      }
      continue;
    }

    await db.execute({
      sql: `INSERT INTO media_items
              (id, type, title, category, status, source_type, source_url, formats, bunny_library,
               is_private, is_locked, dedup_key, last_synced_at, updated_at)
            VALUES (?, 'video', ?, ?, 'published', 'sync', ?, ?, 'private', 1, 1, ?, datetime('now'), datetime('now'))`,
      args: [id, rawTitle, normalizedCategory, sourceUrl, formats, dedupKey]
    });
    imported++;
    details.push({ id, action: 'imported' });
  }

  res.status(200).json({
    source: 'external-catalog',
    endpoint: sourceEndpoint,
    used_fallback: usedFallback,
    private_library_id: PRIVATE.id,
    filtered_out_library,
    previews_count: previews.length,
    imported,
    updated_source,
    unchanged,
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

// ─── Service-to-service: by-destination ───
// Callable by consumer services via Bearer ADMIN_SERVICE_KEY.
// Does NOT require ADMIN_TOKEN so consumer services stay read-only.
async function actionByDestination(req, res, db) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const serviceKey = (process.env.ADMIN_SERVICE_KEY || '').trim();
  if (!serviceKey) return res.status(503).json({ error: 'ADMIN_SERVICE_KEY not configured on server' });

  const auth = (req.headers['authorization'] || '').trim();
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || parts[1].trim() !== serviceKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const dest = getQuery(req).dest;
  if (!dest) return res.status(400).json({ error: 'Missing ?dest= parameter' });

  // Sanitize dest to prevent SQL injection via LIKE pattern
  const safeDest = dest.replace(/[%_\\]/g, c => `\\${c}`);

  const result = await db.execute({
    sql: `SELECT * FROM media_items
          WHERE status = 'published'
            AND (destinations LIKE ? ESCAPE '\\')
            AND (duplicate_status IS NULL OR duplicate_status != 'duplicate')
          ORDER BY date_filmed DESC, date_uploaded DESC`,
    args: [`%"${safeDest}"%`]
  });

  const items = result.rows.map(parseRow).map(signPrivateMediaItem);
  res.status(200).json({ dest, count: items.length, items });
}

// ─── Router ───
const ACTIONS = {
  list: actionList,
  update: actionUpdate,
  delete: actionDelete,
  'import-link': actionImportLink,
  upload: actionUpload,
  'migrate-showcase': actionMigrateShowcase,
  'sync-photos': actionSyncPhotos,
  'sync-videos': actionSyncVideos,
  'sync-external-catalog': actionSyncExternalCatalog,
  'auto-metadata': actionAutoMetadata,
  'lifecycle-batch': actionLifecycleBatch,
  'quality-summary': actionQualitySummary,
  analytics: actionAnalytics,
  'find-duplicates': actionFindDuplicates,
  'resolve-duplicate': actionResolveDuplicate,
  'by-destination': actionByDestination,
};

module.exports = async (req, res) => {
  corsHeaders(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = getQuery(req).action;
  const handler = ACTIONS[action];
  if (!handler) {
    return res.status(400).json({ error: `Unknown action: ${action}`, available: Object.keys(ACTIONS) });
  }

  // by-destination uses its own service-key auth; all other actions require ADMIN_TOKEN
  if (action !== 'by-destination' && !checkAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
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
