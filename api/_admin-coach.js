const { checkAuth, corsHeaders } = require('./_admin-db');

const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';
const DEFAULT_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const VALID_CATEGORIES = new Set(['preview', 'full-movie', 'short-video', 'clip', 'archive', 'feature', 'preview-ever']);
const VALID_FORMATS = new Set(['9x16', '16x9', '1x1']);
const VALID_PRICING_MODES = new Set(['a-la-carte', 'subscription', 'both']);
const VALID_LIFECYCLE_STAGES = new Set(['feature', 'preview-ever', 'archive']);
const VALID_QUALITY_LEVELS = new Set(['draft', 'ready', 'live']);
const DEFAULT_TASK = 'metadata-suggest';

function getExternalCoachSettings() {
  return {
    url: String(process.env.ADMIN_COACH_URL || '').trim(),
    token: String(process.env.ADMIN_COACH_TOKEN || '').trim(),
    timeoutMs: Math.max(1000, Number(process.env.ADMIN_COACH_TIMEOUT_MS || 12000))
  };
}

function sendJson(res, status, payload) {
  res.status(status).json(payload);
}

function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  try {
    return JSON.parse(req.body || '{}');
  } catch (_err) {
    return {};
  }
}

function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function normalizeList(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(',');
  const out = [];
  const seen = new Set();
  for (const item of items) {
    const clean = String(item || '').trim();
    if (!clean) continue;
    const key = clean.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(clean);
  }
  return out;
}

function normalizeRouteTags(value) {
  return normalizeList(value)
    .map(tag => String(tag || '').trim().toLowerCase())
    .filter(tag => tag.startsWith('route:'));
}

function extractJsonPayload(text) {
  const raw = String(text || '').trim();
  if (!raw) return {};

  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : raw;

  try {
    return JSON.parse(candidate);
  } catch (_err) {
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch (_err2) {
        return {};
      }
    }
    return {};
  }
}

function sanitizePatch(input) {
  const data = input && typeof input === 'object' ? input : {};
  const patch = {};

  if (data.title !== undefined) patch.title = String(data.title || '').trim();
  if (data.family_slug !== undefined || data.family !== undefined) {
    patch.family_slug = slugify(data.family_slug || data.family || '');
  }
  if (data.category !== undefined) {
    const category = String(data.category || '').trim().toLowerCase();
    if (VALID_CATEGORIES.has(category)) patch.category = category;
  }
  if (data.description !== undefined) patch.description = String(data.description || '').trim();
  if (data.tags !== undefined) patch.tags = normalizeList(data.tags);
  if (data.date_filmed !== undefined) patch.date_filmed = String(data.date_filmed || '').trim();
  if (data.format !== undefined) {
    const format = String(data.format || '').trim();
    if (VALID_FORMATS.has(format)) patch.format = format;
  }
  if (data.notes !== undefined) patch.notes = String(data.notes || '').trim();
  if (data.source_url !== undefined) patch.source_url = String(data.source_url || '').trim();
  if (data.pricing_mode !== undefined) {
    const pricingMode = String(data.pricing_mode || '').trim().toLowerCase();
    if (VALID_PRICING_MODES.has(pricingMode)) patch.pricing_mode = pricingMode;
  }
  if (data.lifecycle_stage !== undefined) {
    const lifecycleStage = String(data.lifecycle_stage || '').trim().toLowerCase();
    if (VALID_LIFECYCLE_STAGES.has(lifecycleStage)) patch.lifecycle_stage = lifecycleStage;
  }
  if (data.cta_label !== undefined) patch.cta_label = String(data.cta_label || '').trim();
  if (data.quality_level !== undefined) {
    const qualityLevel = String(data.quality_level || '').trim().toLowerCase();
    if (VALID_QUALITY_LEVELS.has(qualityLevel)) patch.quality_level = qualityLevel;
  }
  if (data.sort_order !== undefined && Number.isFinite(Number(data.sort_order))) {
    patch.sort_order = Number(data.sort_order);
  }
  if (data.is_private !== undefined) patch.is_private = !!data.is_private;
  if (data.is_promo !== undefined) patch.is_promo = !!data.is_promo;
  if (data.is_featured !== undefined) patch.is_featured = !!data.is_featured;
  if (data.route_tags !== undefined) patch.route_tags = normalizeRouteTags(data.route_tags);

  return patch;
}

function buildMetadataPrompt(context = {}) {
  const categories = Array.isArray(context.categories) && context.categories.length
    ? context.categories.join(', ')
    : Array.from(VALID_CATEGORIES).join(', ');

  return [
    'Tu es le coach AI d\'un admin de videotheque.',
    'Ta tache ici est uniquement metadata-suggest pour pre-remplir un upload.',
    'Reponds avec du JSON strict uniquement, sans texte autour.',
    'Format attendu: {"patch": {...}, "message": "...", "confidence": 0.0}.',
    'Le champ patch peut contenir uniquement: title, family_slug, category, description, tags, date_filmed, format, notes, source_url, pricing_mode, lifecycle_stage, cta_label, quality_level, sort_order, is_private, is_promo, is_featured, route_tags.',
    `Categories valides: ${categories}.`,
    'Formats valides: 9x16, 16x9, 1x1.',
    'Pricing mode valides: a-la-carte, subscription, both.',
    'Lifecycle stage valides: feature, preview-ever, archive.',
    'Quality level valides: draft, ready, live.',
    'Si une information est absente ou incertaine, omets-la.',
    'family_slug doit etre court, en kebab-case.',
    'tags et route_tags doivent etre des tableaux de chaines.',
    'route_tags doit utiliser le prefixe route:.',
    'message est optionnel et tres court.',
    'confidence est un nombre entre 0 et 1.'
  ].join(' ');
}

function buildAdminAssistPrompt() {
  return [
    'Tu es le coach AI d\'un systeme admin.',
    'Ta tache est d\'aider a la gestion admin generale: organisation, validation, workflow, priorites, structure des metadonnees, routage et hygiene operationnelle.',
    'Reponds avec du JSON strict uniquement, sans texte autour.',
    'Format attendu: {"answer": "...", "actions": ["..."], "warnings": ["..."], "confidence": 0.0}.',
    'answer doit etre court et concret.',
    'actions doit etre une liste courte d\'etapes actionnables.',
    'warnings est optionnel et contient les risques ou points d\'attention.',
    'confidence est un nombre entre 0 et 1.'
  ].join(' ');
}

function sanitizeActions(value) {
  return normalizeList(Array.isArray(value) ? value : [])
    .map(item => String(item || '').trim())
    .filter(Boolean)
    .slice(0, 8);
}

function getTaskConfig(task, context) {
  if (task === 'metadata-suggest') {
    return {
      systemPrompt: buildMetadataPrompt(context),
      sanitizeResponse(parsed) {
        return {
          patch: sanitizePatch(parsed.patch || parsed),
          message: String(parsed.message || '').trim(),
          confidence: Number.isFinite(Number(parsed.confidence))
            ? Math.max(0, Math.min(1, Number(parsed.confidence)))
            : null,
        };
      }
    };
  }

  if (task === 'admin-assist') {
    return {
      systemPrompt: buildAdminAssistPrompt(),
      sanitizeResponse(parsed) {
        return {
          answer: String(parsed.answer || parsed.message || '').trim(),
          actions: sanitizeActions(parsed.actions),
          warnings: sanitizeActions(parsed.warnings),
          confidence: Number.isFinite(Number(parsed.confidence))
            ? Math.max(0, Math.min(1, Number(parsed.confidence)))
            : null,
        };
      }
    };
  }

  const error = new Error('Unsupported coach task');
  error.statusCode = 400;
  throw error;
}

function resolveExternalCoachEndpoint() {
  const settings = getExternalCoachSettings();
  if (!settings.url) return '';
  return /\/api\/admin-coach\/?$/i.test(settings.url)
    ? settings.url.replace(/\/$/, '')
    : `${settings.url.replace(/\/$/, '')}/api/admin-coach`;
}

async function requestExternalCoach(payload) {
  const endpoint = resolveExternalCoachEndpoint();
  if (!endpoint) return null;
  const settings = getExternalCoachSettings();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), settings.timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(settings.token ? { 'Authorization': `Bearer ${settings.token}` } : {})
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`External coach ${response.status}`);
    }

    const data = await response.json();
    return {
      ...data,
      provider: String(data.provider || data.coach || 'external-coach')
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function askOpenAI({ task, message, selections, context, mode }) {
  const apiKey = String(process.env.OPENAI_API_KEY || '').trim();
  if (!apiKey) {
    const error = new Error('AI chat unavailable');
    error.statusCode = 503;
    throw error;
  }

  const taskConfig = getTaskConfig(task, context);
  const userPrompt = JSON.stringify({
    task,
    mode: mode || 'admin-general',
    message,
    selections: selections || {},
    context: context || {}
  });

  const response = await fetch(OPENAI_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: DEFAULT_MODEL,
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: taskConfig.systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    })
  });

  if (!response.ok) {
    const detail = await response.text();
    const error = new Error(`OpenAI API ${response.status}: ${detail}`);
    error.statusCode = 502;
    throw error;
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content || '{}';
  const parsed = extractJsonPayload(content);
  return taskConfig.sanitizeResponse(parsed);
}

async function resolveCoachResponse(payload) {
  const taskConfig = getTaskConfig(payload.task, payload.context);

  if (resolveExternalCoachEndpoint()) {
    try {
      const external = await requestExternalCoach(payload);
      if (external && typeof external === 'object') {
        return {
          task: payload.task,
          coach: 'admin-coach',
          provider: external.provider || 'external-coach',
          ...taskConfig.sanitizeResponse(external)
        };
      }
    } catch (_error) {
      // Keep only-admin autonomous when the external coach is down or unavailable.
    }
  }

  const local = await askOpenAI(payload);
  return {
    task: payload.task,
    coach: 'admin-coach',
    provider: 'local-openai',
    ...local,
  };
}

module.exports = async function handler(req, res) {
  corsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (!checkAuth(req)) {
    return sendJson(res, 401, { error: 'Unauthorized' });
  }

  if (req.method !== 'POST') {
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  const body = parseBody(req);
  const message = String(body.message || '').trim();
  const task = String(body.task || DEFAULT_TASK).trim() || DEFAULT_TASK;
  if (!message) {
    return sendJson(res, 400, { error: 'Message is required' });
  }

  try {
    const result = await resolveCoachResponse({
      task,
      message,
      selections: body.selections || {},
      context: body.context || {},
      mode: body.mode || 'admin-general'
    });
    return sendJson(res, 200, {
      ok: true,
      task: result.task || task,
      coach: result.coach || 'admin-coach',
      provider: result.provider || 'local-openai',
      patch: result.patch || {},
      answer: result.answer || '',
      actions: Array.isArray(result.actions) ? result.actions : [],
      warnings: Array.isArray(result.warnings) ? result.warnings : [],
      message: result.message || '',
      confidence: result.confidence,
    });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 500;
    if (statusCode === 400) return sendJson(res, 400, { error: 'Unsupported coach task' });
    const errorMessage = statusCode === 503 ? 'AI chat unavailable' : 'AI chat failed';
    return sendJson(res, statusCode, { error: errorMessage });
  }
};