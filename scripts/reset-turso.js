#!/usr/bin/env node

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

async function tursoExecuteStatements(statements) {
  const dbUrl = requiredEnv('TURSO_DB_URL').replace('libsql://', 'https://');
  const dbToken = requiredEnv('TURSO_DB_TOKEN');

  const requests = statements.map(sql => ({
    type: 'execute',
    stmt: { sql, args: [] }
  }));
  requests.push({ type: 'close' });

  const resp = await fetch(`${dbUrl}/v2/pipeline`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${dbToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ requests })
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
  const hardMode = process.argv.includes('--hard');
  const confirm = String(process.env.CONFIRM_TURSO_RESET || '').trim().toUpperCase();
  if (confirm !== 'YES') {
    throw new Error('Set CONFIRM_TURSO_RESET=YES to run this destructive command');
  }

  if (hardMode) {
    await tursoExecuteStatements([
      'DROP TABLE IF EXISTS media_items'
    ]);
    console.log('Turso reset hard complete: media_items dropped.');
    return;
  }

  await tursoExecuteStatements([
    'DELETE FROM media_items'
  ]);
  console.log('Turso reset soft complete: media_items rows deleted.');
}

main().catch(err => {
  console.error('[reset-turso] failed:', err.message);
  process.exit(1);
});
