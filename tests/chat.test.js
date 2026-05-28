const express = require('express');
const request = require('supertest');

const coachHandler = require('../api/admin-coach');
const chatAliasHandler = require('../api/chat');

function createApp() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use('/api/admin-coach', (req, res) => coachHandler(req, res));
  app.use('/api/chat', (req, res) => chatAliasHandler(req, res));
  return app;
}

describe('admin coach api basic behavior', () => {
  const originalToken = process.env.ADMIN_TOKEN;
  const originalAllowedOrigins = process.env.ALLOWED_ORIGINS;
  const originalOpenAIKey = process.env.OPENAI_API_KEY;
  const originalCoachUrl = process.env.ADMIN_COACH_URL;
  const originalCoachToken = process.env.ADMIN_COACH_TOKEN;
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.ADMIN_TOKEN = 'test-admin-token';
    process.env.ALLOWED_ORIGINS = 'https://admin.example.com';
    delete process.env.OPENAI_API_KEY;
    delete process.env.ADMIN_COACH_URL;
    delete process.env.ADMIN_COACH_TOKEN;
    global.fetch = originalFetch;
  });

  afterEach(() => {
    process.env.ADMIN_TOKEN = originalToken;
    process.env.ALLOWED_ORIGINS = originalAllowedOrigins;
    process.env.OPENAI_API_KEY = originalOpenAIKey;
    process.env.ADMIN_COACH_URL = originalCoachUrl;
    process.env.ADMIN_COACH_TOKEN = originalCoachToken;
    global.fetch = originalFetch;
  });

  it('responds to OPTIONS and applies allowed origin', async () => {
    const app = createApp();
    const res = await request(app)
      .options('/api/admin-coach')
      .set('Origin', 'https://admin.example.com');

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://admin.example.com');
  });

  it('returns 401 without auth header', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/api/admin-coach')
      .send({ message: 'hello' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Unauthorized' });
  });

  it('returns 503 when openai is not configured', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/api/admin-coach')
      .set('Authorization', 'Bearer test-admin-token')
      .send({ task: 'metadata-suggest', mode: 'upload-assistant', message: 'preview solo famille:chaud-devant' });

    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'AI chat unavailable' });
  });

  it('keeps the legacy chat route as an alias', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/api/chat')
      .set('Authorization', 'Bearer test-admin-token')
      .send({ task: 'metadata-suggest', message: 'preview solo famille:chaud-devant' });

    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'AI chat unavailable' });
  });

  it('returns 400 for unsupported task', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/api/admin-coach')
      .set('Authorization', 'Bearer test-admin-token')
      .send({ task: 'unknown-task', message: 'hello' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Unsupported coach task' });
  });

  it('delegates to external coach when configured', async () => {
    process.env.ADMIN_COACH_URL = 'https://coach.example.com';
    process.env.ADMIN_COACH_TOKEN = 'shared-secret';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({
        task: 'metadata-suggest',
        provider: 'ai-template',
        patch: { category: 'preview', tags: ['solo'] },
        message: 'ok',
        confidence: 0.91,
      })
    });

    const app = createApp();
    const res = await request(app)
      .post('/api/admin-coach')
      .set('Authorization', 'Bearer test-admin-token')
      .send({ task: 'metadata-suggest', message: 'preview solo' });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.provider).toBe('ai-template');
    expect(res.body.patch).toEqual({ category: 'preview', tags: ['solo'] });
  });
});