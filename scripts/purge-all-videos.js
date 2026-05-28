#!/usr/bin/env node

const https = require('https');

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

function httpsJson({ hostname, path, method, headers }, body = null) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path, method, headers }, res => {
      let data = '';
      res.on('data', chunk => {
        data += chunk;
      });
      res.on('end', () => {
        const status = res.statusCode || 0;
        if (status < 200 || status >= 300) {
          return reject(new Error(`${method} ${path} failed (${status}): ${data.slice(0, 300)}`));
        }
        if (!data) return resolve({});
        try {
          resolve(JSON.parse(data));
        } catch (_err) {
          resolve({ raw: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function listLibraryVideos(libraryId, accessKey) {
  const all = [];
  let page = 1;
  const itemsPerPage = 100;

  while (true) {
    const data = await httpsJson({
      hostname: 'video.bunnycdn.com',
      path: `/library/${libraryId}/videos?page=${page}&itemsPerPage=${itemsPerPage}`,
      method: 'GET',
      headers: { AccessKey: accessKey }
    });

    const items = Array.isArray(data.items) ? data.items : [];
    all.push(...items);

    const totalItems = Number(data.totalItems || 0);
    if (items.length === 0 || all.length >= totalItems) break;
    page += 1;
  }

  return all;
}

async function deleteLibraryVideo(libraryId, accessKey, guid) {
  await httpsJson({
    hostname: 'video.bunnycdn.com',
    path: `/library/${libraryId}/videos/${guid}`,
    method: 'DELETE',
    headers: { AccessKey: accessKey }
  });
}

async function purgeLibrary({ name, id, key }) {
  const videos = await listLibraryVideos(id, key);
  console.log(`[purge] ${name}: found ${videos.length} videos`);

  let deleted = 0;
  let failed = 0;
  for (const video of videos) {
    const guid = String(video.guid || '').trim();
    if (!guid) continue;
    try {
      await deleteLibraryVideo(id, key, guid);
      deleted += 1;
    } catch (err) {
      failed += 1;
      console.error(`[purge] ${name} failed guid=${guid}: ${err.message}`);
    }
  }

  return { found: videos.length, deleted, failed };
}

async function purgeTursoVideoRows() {
  const dbUrl = requiredEnv('TURSO_DB_URL').replace('libsql://', 'https://');
  const dbToken = requiredEnv('TURSO_DB_TOKEN');

  const resp = await fetch(`${dbUrl}/v2/pipeline`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${dbToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      requests: [
        {
          type: 'execute',
          stmt: {
            sql: "DELETE FROM media_items WHERE type = 'video'",
            args: []
          }
        },
        { type: 'close' }
      ]
    })
  });

  if (!resp.ok) {
    throw new Error(`Turso API ${resp.status}: ${await resp.text()}`);
  }

  const data = await resp.json();
  const failed = (data.results || []).find(r => r.type === 'error');
  if (failed) {
    throw new Error(`Turso SQL error: ${failed.error?.message || 'unknown error'}`);
  }
}

async function main() {
  const confirm = String(process.env.CONFIRM_PURGE_VIDEOS || '').trim().toUpperCase();
  if (confirm !== 'YES') {
    throw new Error('Set CONFIRM_PURGE_VIDEOS=YES to run this destructive command');
  }

  const publicLib = {
    name: 'public',
    id: requiredEnv('BUNNY_LIBRARY_ID'),
    key: requiredEnv('BUNNY_ACCESS_KEY')
  };
  const privateLib = {
    name: 'private',
    id: requiredEnv('BUNNY_PRIVATE_LIBRARY_ID'),
    key: requiredEnv('BUNNY_PRIVATE_ACCESS_KEY')
  };

  const publicResult = await purgeLibrary(publicLib);
  const privateResult = await purgeLibrary(privateLib);

  await purgeTursoVideoRows();

  console.log('[purge] done');
  console.log(JSON.stringify({ public: publicResult, private: privateResult, turso: 'video rows deleted' }, null, 2));
}

main().catch(err => {
  console.error('[purge] failed:', err.message);
  process.exit(1);
});
