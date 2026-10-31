import { describe, expect, it, vi } from 'vitest';
import { InstrumentationHub } from '../src/index.js';

const observation = {
  correlationId: 'request-1',
};

describe('InstrumentationHub', () => {
  it('delivers sanitized opt-in observations without global interception', async () => {
    const sql = vi.fn();
    const hub = new InstrumentationHub({
      observers: { sql },
    });

    const result = await hub.notifySql({
      ...observation,
      operation: 'select',
      parameterized: true,
      queryFingerprint: 'query-fingerprint',
    });

    expect(result).toEqual({ delivered: true });
    expect(sql).toHaveBeenCalledWith({
      correlationId: 'request-1',
      operation: 'select',
      parameterized: true,
      queryFingerprint: 'query-fingerprint',
    });
  });

  it('isolates observer errors', async () => {
    const hub = new InstrumentationHub({
      observers: {
        authorization: () => {
          throw new Error('observer failure');
        },
      },
    });

    await expect(
      hub.notifyAuthorization({
        ...observation,
        subjectClass: 'user',
        resourceClass: 'account',
        action: 'read',
        allowed: false,
      }),
    ).resolves.toEqual({
      delivered: false,
      failure: { observer: 'authorization', reason: 'error' },
    });
  });

  it('bounds slow observers with a timeout', async () => {
    const hub = new InstrumentationHub({
      timeoutMs: 10,
      observers: {
        command: () => new Promise<void>(() => undefined),
      },
    });

    await expect(
      hub.notifyCommand({
        ...observation,
        executableClass: 'system-tool',
        shellUsed: false,
      }),
    ).resolves.toEqual({
      delivered: false,
      failure: { observer: 'command', reason: 'timeout' },
    });
  });

  it('supports all observer categories with bounded classifications', async () => {
    const observers = {
      outboundHttp: vi.fn(),
      filesystem: vi.fn(),
      command: vi.fn(),
      authorization: vi.fn(),
    };
    const hub = new InstrumentationHub({ observers });

    await hub.notifyOutboundHttp({
      ...observation,
      scheme: 'https',
      hostname: 'example.test',
      resolvedAddressClass: 'public',
    });
    await hub.notifyFilesystem({
      ...observation,
      operation: 'read',
      pathClass: 'application',
      traversalSegments: 0,
    });
    await hub.notifyCommand({
      ...observation,
      executableClass: 'worker',
      shellUsed: false,
    });
    await hub.notifyAuthorization({
      ...observation,
      subjectClass: 'user',
      resourceClass: 'profile',
      action: 'read',
      allowed: true,
    });

    expect(observers.outboundHttp).toHaveBeenCalledOnce();
    expect(observers.filesystem).toHaveBeenCalledOnce();
    expect(observers.command).toHaveBeenCalledOnce();
    expect(observers.authorization).toHaveBeenCalledOnce();
  });
});
