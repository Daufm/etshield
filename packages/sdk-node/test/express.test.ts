import express from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { EthioShield, type TelemetryAdapter } from '../src/index.js';
import type { SecurityEvent } from '@ethioshield/security-contracts';
import { DetectionEngine } from '../src/index.js';

function policy() {
  return {
    schemaVersion: '1.0' as const,
    policyVersion: '1.0',
    enforcementMode: 'enforce' as const,
    defaults: {
      action: 'monitor' as const,
      severity: 'low' as const,
      maxRequestBodyBytes: 1024,
    },
    rules: [],
    routeExclusions: [],
    rateLimit: {
      enabled: false,
      windowSeconds: 60,
      maxRequests: 100,
      keyStrategy: 'ip' as const,
    },
  };
}

function appWith(shield: EthioShield, parser = true) {
  const app = express();
  if (parser) app.use(express.json({ limit: '1kb' }));
  app.use(shield.protect());
  app.get('/health', (_request, response) => response.json({ status: 'ok' }));
  app.post('/search', (request, response) => response.json({ received: request.body }));
  app.get('/files/:name', (_request, response) => response.json({ status: 'ok' }));
  return app;
}

describe('EthioShield Express middleware', () => {
  it('preserves benign application behavior and reports a structured decision', async () => {
    const onDecision = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      onDecision,
    });

    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
    expect(response.headers['x-ethioshield-action']).toBe('allow');
    expect(onDecision).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'allow' }),
      expect.objectContaining({
        event: expect.any(Object),
        correlationId: expect.any(String),
      }),
    );
    await shield.close();
  });

  it('defaults to monitor and does not block detected requests', async () => {
    const telemetry: TelemetryAdapter = { emit: vi.fn() };
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      telemetry,
    });

    const response = await request(appWith(shield)).get('/files/%2e%2e%2fetc%2fpasswd');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
    expect(response.headers['x-ethioshield-action']).toBe('monitor');
    expect(telemetry.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: expect.objectContaining({ action: 'monitor' }),
      }),
    );
    await shield.close();
  });

  it('blocks findings with a controlled response in block mode', async () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      mode: 'block',
    });

    const response = await request(appWith(shield)).post('/search').send({
      search: 'UNION SELECT username FROM users',
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: 'Request blocked by security policy' });
    expect(JSON.stringify(response.body)).not.toContain('UNION');
    await shield.close();
  });

  it('fails closed when a relevant body is unavailable before an upstream parser', async () => {
    const onDecision = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      mode: 'block',
      onDecision,
    });

    const response = await request(appWith(shield, false)).post('/search').send({
      search: 'UNION SELECT username FROM users',
    });

    expect(response.status).toBe(503);
    expect(onDecision).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'block' }),
      expect.any(Object),
    );
    await shield.close();
  });

  it('continues in monitor mode with a non-clean decision when a body is unavailable', async () => {
    const onDecision = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      onDecision,
    });

    const response = await request(appWith(shield, false)).post('/search').send({
      search: 'UNION SELECT username FROM users',
    });

    expect(response.status).toBe(200);
    expect(response.headers['x-ethioshield-action']).toBe('monitor');
    expect(onDecision).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'monitor',
        reason: expect.objectContaining({ code: 'inspection_failed' }),
      }),
      expect.any(Object),
    );
    await shield.close();
  });

  it('returns a controlled failure when detection fails in block mode', async () => {
    const engine = new DetectionEngine([
      {
        ruleId: 'test.detector_failure',
        detect: () => {
          throw new Error('detector failure');
        },
      },
    ]);
    const onError = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      mode: 'block',
      engine,
      onError,
    });

    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(503);
    expect(response.body).toEqual({ error: 'Security inspection unavailable' });
    expect(onError).toHaveBeenCalledWith({
      code: 'detection_error',
      message: 'Security inspection failed.',
    });
    await shield.close();
  });

  it('does not let telemetry failures alter the decision or request', async () => {
    const telemetry: TelemetryAdapter = {
      emit: async () => {
        throw new Error('telemetry failure');
      },
    };
    const onError = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      telemetry,
      onError,
    });

    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(200);
    expect(response.headers['x-ethioshield-action']).toBe('allow');
    expect(onError).toHaveBeenCalledWith({
      code: 'telemetry_error',
      message: 'Telemetry delivery failed.',
    });
    await shield.close();
  });

  it('bounds a slow telemetry adapter and cleans it up on shutdown', async () => {
    const onError = vi.fn();
    const close = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      telemetry: {
        emit: () => new Promise<void>(() => undefined),
        close,
      },
      onError,
    });

    const started = performance.now();
    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(200);
    expect(performance.now() - started).toBeLessThan(500);
    await shield.close();
    expect(close).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith({
      code: 'telemetry_error',
      message: 'Telemetry delivery failed.',
    });
  });

  it('honors safe route exclusions and validates proxy-derived metadata', async () => {
    const events: SecurityEvent[] = [];
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      routeExclusions: ['/health'],
      trustedProxy: { addresses: ['127.0.0.1'] },
      telemetry: { emit: (event) => events.push(event) },
    });

    const response = await request(appWith(shield))
      .get('/health')
      .set('x-forwarded-for', '203.0.113.10');

    expect(response.status).toBe(200);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      decision: {
        action: 'monitor',
        ruleId: 'policy.route_exclusion',
        reason: { code: 'route_excluded' },
      },
    });
    await shield.close();
  });

  it('does not apply a method-scoped exclusion to other methods', async () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: {
        ...policy(),
        routeExclusions: [{ route: '/search', methods: ['GET'] }],
      },
      mode: 'block',
    });

    const response = await request(appWith(shield))
      .post('/search')
      .send({ search: 'UNION SELECT username FROM users' });

    expect(response.status).toBe(403);
    await shield.close();
  });

  it('fails closed when trusted identity resolution throws in block mode', async () => {
    const onError = vi.fn();
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      mode: 'block',
      trustedIdentity: () => {
        throw new Error('identity failure');
      },
      onError,
    });

    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(503);
    expect(response.body).toEqual({ error: 'Security inspection unavailable' });
    expect(onError).toHaveBeenCalledWith({
      code: 'identity_error',
      message: 'Trusted identity resolution failed.',
    });
    await shield.close();
  });

  it('throttles by trusted target account identity rather than spoofable headers', async () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: {
        ...policy(),
        rateLimit: {
          ...policy().rateLimit,
          enabled: true,
          rules: [
            {
              ruleId: 'account.login',
              keyTypes: ['target_account'],
              windowSeconds: 60,
              maxRequests: 1,
              action: 'throttle',
            },
          ],
        },
      },
      trustedIdentity: () => ({ targetAccountId: 'account-1' }),
    });

    await request(appWith(shield))
      .get('/health')
      .set('x-ethioshield-user-id', 'attacker-controlled');
    const response = await request(appWith(shield))
      .get('/health')
      .set('x-ethioshield-user-id', 'different-attacker-controlled');

    expect(response.status).toBe(429);
    expect(response.body).toEqual({ error: 'Request throttled by security policy' });
    expect(response.headers['retry-after']).toBeDefined();
    await shield.close();
  });

  it('applies trusted account correlation across changing client IPs', async () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: {
        ...policy(),
        correlation: {
          enabled: true,
          rules: [
            {
              ruleId: 'account.behavior',
              dimensions: ['target_account'],
              windowSeconds: 60,
              maxEvents: 1,
              action: 'block',
            },
          ],
        },
      },
      trustedProxy: { addresses: ['127.0.0.1'] },
      trustedIdentity: () => ({ targetAccountId: 'account-1' }),
    });

    const app = appWith(shield);
    expect((await request(app).get('/health').set('x-forwarded-for', '198.51.100.1')).status).toBe(
      200,
    );
    expect((await request(app).get('/health').set('x-forwarded-for', '198.51.100.2')).status).toBe(
      403,
    );
    await shield.close();
  });

  it('does not block a VPN classification by itself', async () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: policy(),
      mode: 'block',
      trustedProxy: { addresses: ['127.0.0.1'] },
      networkIntelligence: {
        resolve: async () => ({
          kind: 'network_intelligence',
          classification: 'vpn',
          confidence: 1,
          provenance: 'test',
          observedAt: '2026-10-31T05:00:00.000Z',
          expiresAt: '2099-10-31T05:00:00.000Z',
        }),
      },
    });

    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(200);
    await shield.close();
  });

  it('uses a challenge adapter only when a configured rule requests challenge', async () => {
    const challenge = vi.fn(async (_request, response) => {
      response.status(429).json({ error: 'challenge' });
      return { handled: true };
    });
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: {
        ...policy(),
        rateLimit: {
          ...policy().rateLimit,
          enabled: true,
          rules: [
            {
              ruleId: 'challenge.login',
              keyTypes: ['target_account'],
              windowSeconds: 60,
              maxRequests: 1,
              action: 'challenge',
            },
          ],
        },
      },
      trustedIdentity: () => ({ targetAccountId: 'account-1' }),
      challengeAdapter: { challenge },
    });

    await request(appWith(shield)).get('/health');
    const response = await request(appWith(shield)).get('/health');

    expect(response.status).toBe(429);
    expect(response.body).toEqual({ error: 'challenge' });
    expect(challenge).toHaveBeenCalledOnce();
    await shield.close();
  });
});
