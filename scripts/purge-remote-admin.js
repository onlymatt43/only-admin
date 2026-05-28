#!/usr/bin/env node

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

async function apiRequest(baseUrl, token, path, method = 'GET') {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text || '{}');
  } catch (_err) {
    body = { raw: text };
  }

  if (!res.ok) {
    throw new Error(`${method} ${path} failed (${res.status}): ${JSON.stringify(body).slice(0, 400)}`);
  }

  return body;
}

async function main() {
  const confirm = String(process.env.CONFIRM_PURGE_VIDEOS || '').trim().toUpperCase();
  if (confirm !== 'YES') {
    throw new Error('Set CONFIRM_PURGE_VIDEOS=YES to run this destructive command');
  }

  const baseUrl = requiredEnv('ADMIN_BASE_URL').replace(/\/$/, '');
  const token = requiredEnv('ADMIN_TOKEN');

  const list = await apiRequest(baseUrl, token, '/api/admin-api?action=list', 'GET');
  const items = Array.isArray(list.items) ? list.items : [];
  const videos = items.filter(item => String(item.type || '').toLowerCase() === 'video');

  console.log(`[remote-purge] found ${videos.length} videos`);

  let deleted = 0;
  let failed = 0;
  for (const item of videos) {
    const id = encodeURIComponent(String(item.id || '').trim());
    if (!id) continue;
    try {
      await apiRequest(baseUrl, token, `/api/admin-api?action=delete&id=${id}&deleteCdn=true`, 'DELETE');
      deleted += 1;
    } catch (err) {
      failed += 1;
      console.error(`[remote-purge] failed id=${id}: ${err.message}`);
    }
  }

  console.log(JSON.stringify({ found: videos.length, deleted, failed }, null, 2));

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('[remote-purge] failed:', err.message);
  process.exit(1);
});
