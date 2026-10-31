import express from 'express';
import { EthioShield } from '@ethioshield/sdk-node';
import { isHttpMethod } from '@ethioshield/security-contracts';

const app = express();
const shield = new EthioShield({
  projectId: 'playground',
  policy: {
    schemaVersion: '1.0',
    policyVersion: '1.0',
    enforcementMode: 'monitor',
    defaults: {
      action: 'monitor',
      severity: 'low',
      maxRequestBodyBytes: 1_048_576,
    },
    rules: [],
    routeExclusions: [],
    rateLimit: {
      enabled: false,
      windowSeconds: 60,
      maxRequests: 100,
      keyStrategy: 'ip',
    },
  },
});

app.get('/health', (_request, response) => {
  response.json({ status: 'ok' });
});

app.use((request, response, next) => {
  if (!isHttpMethod(request.method)) {
    response.status(400).json({ error: 'Unsupported HTTP method' });
    return;
  }
  const result = shield.evaluate({ method: request.method, path: request.path });
  response.setHeader('x-ethioshield-decision', result.decision.action);
  next();
});

app.get('/', (_request, response) => {
  response.json({ service: 'ethioshield-playground', status: 'experimental' });
});

export { app };
