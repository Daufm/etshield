import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { app } from '../../apps/playground/src/index.js';

describe('playground integration', () => {
  it('exposes a health endpoint', async () => {
    const response = await request(app).get('/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
  });

  it('adds an EthioShield decision header to application requests', async () => {
    const response = await request(app).get('/');

    expect(response.status).toBe(200);
    expect(response.headers['x-ethioshield-decision']).toBe('monitor');
  });
});
