const express = require('express');
const request = require('supertest');

const handler = require('../api/image-proxy');

function createApp() {
  const app = express();
  app.use('/api/image-proxy', (req, res) => handler(req, res));
  return app;
}

describe('image-proxy safety checks', () => {
  const originalAllowedOrigins = process.env.ALLOWED_ORIGINS;

  beforeEach(() => {
    process.env.ALLOWED_ORIGINS = 'https://admin.example.com';
  });

  afterEach(() => {
    process.env.ALLOWED_ORIGINS = originalAllowedOrigins;
  });

  it('responds to OPTIONS and applies allowed origin', async () => {
    const app = createApp();
    const res = await request(app)
      .options('/api/image-proxy')
      .set('Origin', 'https://admin.example.com');

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://admin.example.com');
  });

  it('blocks localhost target host', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/api/image-proxy?url=http://localhost/image.jpg');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Blocked host' });
  });

  it('rejects unsupported protocol', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/api/image-proxy?url=file:///etc/passwd');

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Unsupported url protocol' });
  });
});
