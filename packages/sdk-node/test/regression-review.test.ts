import express from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import type { SecurityEvent, SecurityPolicy } from '@ethioshield/security-contracts';
import {
  DetectionEngine,
  EthioShield,
  sanitizeEventRoute,
  type TelemetryAdapter,
} from '../src/index.js';

type AsyncTest = () => void | Promise<void>;

async function knownBug(id: string, fn: AsyncTest): Promise<void> {
  try {
    await fn();
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'name' in error &&
      error.name === 'AssertionError'
    ) {
      return;
    }
    throw error;
  }
  throw new Error(`${id} now passes: remove knownBug wrapper`);
}

function policy(overrides: Partial<SecurityPolicy> = {}): SecurityPolicy {
  return {
    schemaVersion: '1.0',
    policyVersion: '1.0',
    enforcementMode: 'enforce',
    defaults: { action: 'monitor', severity: 'low', maxRequestBodyBytes: 65_536 },
    rules: [],
    routeExclusions: [],
    rateLimit: {
      enabled: false,
      windowSeconds: 60,
      maxRequests: 100,
      keyStrategy: 'ip',
    },
    ...overrides,
  };
}

function appWithShield(
  shield: EthioShield,
  setup: (app: express.Express) => void = (app) => {
    app.get('/health', (_request, response) => response.json({ status: 'ok' }));
    app.get('/s', (_request, response) => response.json({ status: 'ok' }));
    app.get('/files/:name', (_request, response) => response.json({ status: 'ok' }));
  },
): express.Express {
  const app = express();
  app.use(express.json({ limit: '128kb' }));
  app.use(shield.protect());
  setup(app);
  return app;
}

describe('architecture review regression cases', () => {
  it('M1 findings win over a normalization degradation', async () => {
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      mode: 'block',
      engine: new DetectionEngine(undefined, {
        budget: {
          maxInputBytes: 1_048_576,
          maxNodes: 1_000,
          maxDepth: 8,
          maxValues: 1_000,
          maxFindings: 50,
          maxDurationMs: 1_000,
        },
      }),
    });
    try {
      const app = appWithShield(shield, (configured) => {
        configured.post('/json', (req, res) => res.json({ received: req.body }));
      });
      const response = await request(app)
        .post('/json')
        .send({ value: `${'<script>'.repeat(20)}${'x'.repeat(20_000)}` });
      expect(response.status).toBe(403);
    } finally {
      await shield.close();
    }
  });

  it('M1 degradedAction block returns a controlled incomplete response', async () => {
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      mode: 'block',
      inspection: { degradedAction: 'block' },
    });
    try {
      const app = appWithShield(shield, (configured) => {
        configured.post('/json', (req, res) => res.json({ received: req.body }));
      });
      const response = await request(app).post('/json').send({ value: 'x'.repeat(20_000) });
      expect(response.status).toBe(503);
      expect(response.body).toEqual({ error: 'Security inspection incomplete' });
    } finally {
      await shield.close();
    }
  });

  it('M1 component-specific malformed encoding handling', () => {
    const engine = new DetectionEngine([]);
    expect(engine.inspect({ method: 'GET', route: '/x%zz', query: { q: '%zz' }, body: { q: '%zz' } })).toMatchObject({
      outcome: 'failed',
      normalization: { malformedEncoding: true },
    });
    expect(
      engine.inspect({ method: 'GET', route: '/x', query: { q: '%zz' }, body: { q: '%zz' } }),
    ).toMatchObject({
      outcome: 'clean',
      normalization: { malformedEncoding: false },
    });
  });

  it('M1 sanitizes padded and repeated-slash event routes', async () => {
    const events: SecurityEvent[] = [];
    const onDecision = vi.fn();
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      telemetry: { emit: (event) => events.push(event) },
      onDecision,
    });
    try {
      const app = appWithShield(shield, (configured) => {
        configured.get('/files/*splat', (_req, res) => res.json({ status: 'ok' }));
      });
      await request(app).get(`/files/${'a'.repeat(600)}/../etc`);
      await request(app).get('//files//abc');
      expect(events.length).toBeGreaterThanOrEqual(1);
      expect(onDecision).toHaveBeenCalledTimes(2);
      const rawPaths = [`/files/${'a'.repeat(600)}/../etc`, '//files//abc'];
      for (const event of events) {
        expect(event.request.route.length).toBeLessThanOrEqual(512);
        for (const rawPath of rawPaths) {
          expect(event.request.route).not.toBe(rawPath);
        }
      }
    } finally {
      await shield.close();
    }
  });

  it('M1 sanitizeEventRoute preserves valid routes and is deterministic', () => {
    expect(sanitizeEventRoute('/health')).toBe('/health');
    expect(sanitizeEventRoute('/a//b?x#y\u0000')).toBe('/a/b_x_y_');
    const route = `/${'x'.repeat(600)}`;
    expect(sanitizeEventRoute(route)).toBe(sanitizeEventRoute(route));
    expect(sanitizeEventRoute(route).length).toBeLessThanOrEqual(512);
    expect(sanitizeEventRoute(route)).not.toContain('\u0000');
  });

  it.each([
    ['block', 'block', 503],
    ['monitor', 'monitor', 200],
  ] as const)('M1 handle rejection in %s mode is contained', async (mode, expectedMode, status) => {
    const onError = vi.fn();
    const unhandledRejections: unknown[] = [];
    const onUnhandledRejection = (error: unknown) => unhandledRejections.push(error);
    process.on('unhandledRejection', onUnhandledRejection);
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      mode,
      onError,
    });
    const handle = vi.spyOn(shield as unknown as { handle: () => Promise<void> }, 'handle');
    handle.mockRejectedValue(new Error('forced rejection'));
    try {
      const response = await request(appWithShield(shield)).get('/health');
      expect(response.status).toBe(status);
      expect(expectedMode).toBe(mode);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'internal_error' }),
      );
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandledRejections).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandledRejection);
      await shield.close();
    }
  });

  it.each([
    ['A1.1 q=50%25', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        const app = appWithShield(shield);
        expect((await request(app).get('/s?q=50%25')).status).toBe(200);
      } finally {
        await shield.close();
      }
    }],
    ['A1.2 20k field', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        const app = appWithShield(shield, (configured) => {
          configured.post('/json', (req, res) => res.json({ received: req.body }));
        });
        expect((await request(app).post('/json').send({ value: 'x'.repeat(20_000) })).status).toBe(
          200,
        );
      } finally {
        await shield.close();
      }
    }],
    ['A1.3 300 objects', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        const app = appWithShield(shield, (configured) => {
          configured.post('/json', (req, res) => res.json({ received: req.body }));
        });
        const body = Array.from({ length: 300 }, (_, id) => ({ id, name: 'item', qty: 1 }));
        expect((await request(app).post('/json').send(body)).status).toBe(200);
      } finally {
        await shield.close();
      }
    }],
    ['A1.4 //health', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        expect((await request(appWithShield(shield)).get('//health')).status).not.toBe(503);
      } finally {
        await shield.close();
      }
    }],
    ['A1.5 q=windows', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        expect((await request(appWithShield(shield)).get('/s?q=windows')).status).toBe(200);
      } finally {
        await shield.close();
      }
    }],
    ['A1.6 /files/etc', async () => {
      const shield = new EthioShield({ projectId: 'regression', policy: policy(), mode: 'block' });
      try {
        expect((await request(appWithShield(shield)).get('/files/etc')).status).toBe(200);
      } finally {
        await shield.close();
      }
    }],
  ])('A1 %s', async (name, fn) => {
    // Observed today: 503 (50%25, 20k field, 300 objects, //health) and 403 (windows, /files/etc).
    if (name === 'A1.5 q=windows' || name === 'A1.6 /files/etc') {
      await knownBug(name, fn);
      return;
    }
    await fn();
  });

  it.each([
    ['B1.1 recorded client ip', async () => {
      const events: SecurityEvent[] = [];
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy(),
        mode: 'block',
        trustedProxy: { addresses: ['127.0.0.1'] },
        telemetry: { emit: (event) => events.push(event) },
      });
      try {
        const app = appWithShield(shield);
        await request(app).get('/health').set('x-forwarded-for', '6.6.6.6, 10.0.0.9');
        expect(events[0]?.client?.ip).toBe('10.0.0.9');
      } finally {
        await shield.close();
      }
    }],
    ['B1.2 rotating XFF', async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({
          rateLimit: {
            enabled: true,
            windowSeconds: 60,
            maxRequests: 100,
            keyStrategy: 'ip',
            rules: [
              { ruleId: 'ip.limit', keyTypes: ['ip'], windowSeconds: 60, maxRequests: 2, action: 'block' },
            ],
            failureMode: 'block',
          },
        }),
        mode: 'block',
        trustedProxy: { addresses: ['127.0.0.1'] },
      });
      try {
        const app = appWithShield(shield);
        const responses = await Promise.all(
          Array.from({ length: 6 }, (_, index) =>
            request(app).get('/health').set('x-forwarded-for', `6.6.6.${index + 1}, 10.0.0.9`),
          ),
        );
        expect(responses.filter((response) => response.status === 403)).toHaveLength(4);
      } finally {
        await shield.close();
      }
    }],
  ])('B1 %s', async (name, fn) => {
    // Observed today: recorded ip '6.6.6.6' and 6/6 requests allowed.
    await knownBug(name, fn);
  });

  it('B2', async () => {
    // Observed today: 4/4 allowed.
    await knownBug('B2', async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({
          rateLimit: {
            enabled: true,
            windowSeconds: 60,
            maxRequests: 100,
            keyStrategy: 'ip',
            rules: [
              { ruleId: 'ip.limit', keyTypes: ['ip'], windowSeconds: 60, maxRequests: 1, action: 'block' },
            ],
            failureMode: 'block',
          },
        }),
        mode: 'block',
      });
      try {
        const responses = await Promise.all(
          Array.from({ length: 4 }, () => request(appWithShield(shield)).get('/health')),
        );
        expect(responses.filter((response) => response.status === 403)).toHaveLength(3);
      } finally {
        await shield.close();
      }
    });
  });

  it.each([
    ['B4.1 /Login', '/api/Login'],
    ['B4.2 /login/', '/api/login/'],
  ])('%s', async (name, path) => {
    // Observed today: '/Login' and '/login/' 6/6 allowed, mounted route recorded without '/api'.
    await knownBug(name, async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({
          rateLimit: {
            enabled: true,
            windowSeconds: 60,
            maxRequests: 100,
            keyStrategy: 'ip',
            rules: [
              { ruleId: 'login.limit', keyTypes: ['route'], route: '/login', windowSeconds: 60, maxRequests: 2, action: 'block' },
            ],
            failureMode: 'block',
          },
        }),
        mode: 'block',
      });
      try {
        const app = express();
        app.use('/api', shield.protect());
        app.get('/api/Login', (_req, res) => res.json({ status: 'ok' }));
        app.get('/api/login/', (_req, res) => res.json({ status: 'ok' }));

        const responses = await Promise.all([
          request(app).get(path),
          request(app).get(path),
          request(app).get(path),
        ]);
        expect(responses[2]?.status).toBe(403);
      } finally {
        await shield.close();
      }
    });
  });

  it('B4.3 mounted route keeps /api', async () => {
    // Observed today: '/Login' and '/login/' 6/6 allowed, mounted route recorded without '/api'.
    await knownBug('B4.3', async () => {
      const events: SecurityEvent[] = [];
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy(),
        telemetry: { emit: (event) => events.push(event) },
      });
      try {
        const app = express();
        app.use('/api', shield.protect());
        app.get('/health', (_req, res) => res.json({ status: 'ok' }));
        await request(app).get('/api/health');
        expect(events.some((event) => event.request.route.startsWith('/api'))).toBe(true);
      } finally {
        await shield.close();
      }
    });
  });

  it('B5.1 policy maxRequests ignored', async () => {
    // Observed today: maxRequests=1 -> 4/4 allowed, policy monitor + mode block -> 403.
    await knownBug('B5.1', async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({
          rateLimit: { enabled: true, windowSeconds: 60, maxRequests: 1, keyStrategy: 'ip' },
        }),
        mode: 'block',
      });
      try {
        const responses = await Promise.all(
          Array.from({ length: 4 }, () => request(appWithShield(shield)).get('/health')),
        );
        expect(responses.filter((response) => response.status === 403)).toHaveLength(3);
      } finally {
        await shield.close();
      }
    });
  });

  it('B5.2 policy monitor + options.mode block', async () => {
    // Observed today: maxRequests=1 -> 4/4 allowed, policy monitor + mode block -> 403.
    await knownBug('B5.2', async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({ enforcementMode: 'monitor' }),
        mode: 'block',
      });
      try {
        expect((await request(appWithShield(shield)).get('/s?q=UNION%20SELECT')).status).not.toBe(403);
      } finally {
        await shield.close();
      }
    });
  });

  it('B6', async () => {
    // Observed today: 200 'monitor'.
    await knownBug('B6', async () => {
      const shield = new EthioShield({
        projectId: 'regression',
        policy: policy({
          rules: [
            { ruleId: 'input.sql_injection_indicator', category: 'input', enabled: true, action: 'monitor' },
            { ruleId: 'input.xss_indicator', category: 'input', enabled: true, action: 'block' },
          ],
        }),
        mode: 'block',
      });
      try {
        const app = appWithShield(shield, (configured) => {
          configured.get('/search', (_req, res) => res.json({ status: 'ok' }));
        });
        const response = await request(app).get(
          "/search?q=' OR '1'='1&next=%3Cbody%20onload%3Dalert(1)%3E",
        );
        expect(response.status).toBe(403);
      } finally {
        await shield.close();
      }
    });
  });

  it('B7', async () => {
    // Observed today: 0 events and 0 decisions; onError receives event_error.
    const events: SecurityEvent[] = [];
    const onDecision = vi.fn();
    const onError = vi.fn();
    const telemetry: TelemetryAdapter = { emit: (event) => events.push(event) };
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      telemetry,
      onDecision,
      onError,
    });
    try {
      const app = appWithShield(shield, (configured) => {
        configured.get('/files/*splat', (_req, res) => res.json({ status: 'ok' }));
      });
      expect((await request(app).get(`/files/${'a'.repeat(600)}/../etc`)).status).toBe(200);
      expect(events.length).toBeGreaterThanOrEqual(1);
      expect(onDecision).toHaveBeenCalled();
    } finally {
      await shield.close();
    }
  });

  it('B7 current event_error diagnostic', async () => {
    const onError = vi.fn();
    const shield = new EthioShield({
      projectId: 'regression',
      policy: policy(),
      onError,
      eventId: () => '',
    });
    try {
      const app = appWithShield(shield);
      await request(app).get(`/files/${'a'.repeat(600)}/../etc`);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'event_error' }),
      );
    } finally {
      await shield.close();
    }
  });

  it.each([
    ["C1 attack ' OR '1'='1", "' OR '1'='1", true],
    ["C1 attack 1' UNION SELECT NULL--", "1' UNION SELECT NULL--", true],
    ['C1 attack UNION/**/SELECT 1', 'UNION/**/SELECT 1', true],
    ['C1 attack body onload', '<body onload=alert(1)>', true],
    ['C1 benign delete from cart', 'delete from cart', false],
    ['C1 benign Please select from the list', 'Please select from the list', false],
    ['C1 benign windows', 'windows', false],
    ['C1 benign etc', 'etc', false],
    ['C1 benign javascript: the good parts', 'javascript: the good parts', false],
  ])('%s', async (name, input, expected) => {
    // Observed today: misses the 4 attacks and flags the 5 benign inputs.
    await knownBug(name, () => {
      const result = new DetectionEngine().inspect({
        method: 'GET',
        route: '/probe',
        query: { value: input },
      });
      expect(result.findings.length > 0).toBe(expected);
    });
  });
});
