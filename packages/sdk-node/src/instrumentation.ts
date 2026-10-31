export interface InstrumentationBase {
  readonly correlationId: string;
}

export interface SqlObservation extends InstrumentationBase {
  readonly operation: string;
  readonly parameterized: boolean;
  readonly queryFingerprint?: string;
}

export interface OutboundHttpObservation extends InstrumentationBase {
  readonly scheme: string;
  readonly hostname: string;
  readonly resolvedAddressClass?: 'public' | 'private' | 'loopback' | 'link_local';
}

export interface FilesystemObservation extends InstrumentationBase {
  readonly operation: 'read' | 'write' | 'delete';
  readonly pathClass: 'relative' | 'absolute' | 'system' | 'application';
  readonly traversalSegments: number;
}

export interface CommandObservation extends InstrumentationBase {
  readonly executableClass: string;
  readonly shellUsed: boolean;
}

export interface AuthorizationObservation extends InstrumentationBase {
  readonly subjectClass: string;
  readonly resourceClass: string;
  readonly action: string;
  readonly allowed: boolean;
}

export interface InstrumentationObservers {
  readonly sql?: (observation: SqlObservation) => void | Promise<void>;
  readonly outboundHttp?: (observation: OutboundHttpObservation) => void | Promise<void>;
  readonly filesystem?: (observation: FilesystemObservation) => void | Promise<void>;
  readonly command?: (observation: CommandObservation) => void | Promise<void>;
  readonly authorization?: (observation: AuthorizationObservation) => void | Promise<void>;
}

export interface InstrumentationOptions {
  readonly observers: InstrumentationObservers;
  readonly timeoutMs?: number;
}

export interface InstrumentationFailure {
  readonly observer: 'sql' | 'outboundHttp' | 'filesystem' | 'command' | 'authorization';
  readonly reason: 'error' | 'timeout';
}

export interface InstrumentationResult {
  readonly delivered: boolean;
  readonly failure?: InstrumentationFailure;
}

const DEFAULT_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 1_000;
const MAX_IDENTIFIER_LENGTH = 128;

function bounded(value: string): string {
  return value.slice(0, MAX_IDENTIFIER_LENGTH);
}

async function withTimeout(
  operation: Promise<void>,
  timeoutMs: number,
  observer: InstrumentationFailure['observer'],
): Promise<InstrumentationResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<InstrumentationResult>((resolve) => {
    timer = setTimeout(
      () => resolve({ delivered: false, failure: { observer, reason: 'timeout' } }),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation.then(() => ({ delivered: true })), timeout]);
  } catch {
    return { delivered: false, failure: { observer, reason: 'error' } };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class InstrumentationHub {
  private readonly observers: InstrumentationObservers;
  private readonly timeoutMs: number;

  public constructor(options: InstrumentationOptions) {
    if (
      !Number.isInteger(options.timeoutMs ?? DEFAULT_TIMEOUT_MS) ||
      (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) < 1 ||
      (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) > MAX_TIMEOUT_MS
    ) {
      throw new TypeError(`timeoutMs must be an integer between 1 and ${MAX_TIMEOUT_MS}`);
    }
    this.observers = options.observers;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  public notifySql(observation: SqlObservation): Promise<InstrumentationResult> {
    return this.notify('sql', this.observers.sql, {
      ...observation,
      correlationId: bounded(observation.correlationId),
      operation: bounded(observation.operation),
      ...(observation.queryFingerprint === undefined
        ? {}
        : { queryFingerprint: bounded(observation.queryFingerprint) }),
    });
  }

  public notifyOutboundHttp(observation: OutboundHttpObservation): Promise<InstrumentationResult> {
    return this.notify('outboundHttp', this.observers.outboundHttp, {
      ...observation,
      correlationId: bounded(observation.correlationId),
      scheme: bounded(observation.scheme),
      hostname: bounded(observation.hostname),
    });
  }

  public notifyFilesystem(observation: FilesystemObservation): Promise<InstrumentationResult> {
    return this.notify('filesystem', this.observers.filesystem, {
      ...observation,
      correlationId: bounded(observation.correlationId),
    });
  }

  public notifyCommand(observation: CommandObservation): Promise<InstrumentationResult> {
    return this.notify('command', this.observers.command, {
      ...observation,
      correlationId: bounded(observation.correlationId),
      executableClass: bounded(observation.executableClass),
    });
  }

  public notifyAuthorization(
    observation: AuthorizationObservation,
  ): Promise<InstrumentationResult> {
    return this.notify('authorization', this.observers.authorization, {
      ...observation,
      correlationId: bounded(observation.correlationId),
      subjectClass: bounded(observation.subjectClass),
      resourceClass: bounded(observation.resourceClass),
      action: bounded(observation.action),
    });
  }

  private async notify<T extends InstrumentationBase>(
    observerName: InstrumentationFailure['observer'],
    observer: ((observation: T) => void | Promise<void>) | undefined,
    observation: T,
  ): Promise<InstrumentationResult> {
    if (observer === undefined) return { delivered: true };
    const result = await withTimeout(
      Promise.resolve().then(() => observer(observation)),
      this.timeoutMs,
      observerName,
    );
    return result;
  }
}
