const express = require('express');
const request = require('supertest');

const handler = require('../api/admin-api');

function createApp() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use('/api/admin-api', (req, res) => handler(req, res));
  return app;
}

describe('admin-api basic behavior', () => {
  const originalToken = process.env.ADMIN_TOKEN;
  const originalAllowedOrigins = process.env.ALLOWED_ORIGINS;

  beforeEach(() => {
    process.env.ADMIN_TOKEN = 'test-admin-token';
    process.env.ALLOWED_ORIGINS = 'https://admin.example.com';
  });

  afterEach(() => {
    process.env.ADMIN_TOKEN = originalToken;
    process.env.ALLOWED_ORIGINS = originalAllowedOrigins;
  });

  it('returns 400 for unknown action', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/api/admin-api?action=unknown-action')
      .set('Origin', 'https://admin.example.com');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Unknown action');
    expect(Array.isArray(res.body.available)).toBe(true);
    expect(res.headers['access-control-allow-origin']).toBe('https://admin.example.com');
  });

  it('returns 401 for protected action without auth header', async () => {
    const app = createApp();
    const res = await request(app).get('/api/admin-api?action=list');

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Unauthorized' });
  });
});
