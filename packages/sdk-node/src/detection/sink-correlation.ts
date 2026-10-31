import type { DetectionFinding, DetectionResult } from './types.js';
import type {
  AuthorizationObservation,
  CommandObservation,
  FilesystemObservation,
  InstrumentationResult,
  OutboundHttpObservation,
  SqlObservation,
} from '../instrumentation.js';

export type SinkObservation =
  | SqlObservation
  | OutboundHttpObservation
  | FilesystemObservation
  | CommandObservation
  | AuthorizationObservation;

export type SinkKind = 'sql' | 'outboundHttp' | 'filesystem' | 'command' | 'authorization';

export type ExploitabilityStatus =
  | 'request_indicator'
  | 'sink_observed'
  | 'correlated_exploitability';

export interface CorrelatedFinding {
  readonly status: ExploitabilityStatus;
  readonly requestFinding: DetectionFinding;
  readonly sink: SinkKind;
  readonly correlationId: string;
  readonly confidence: 'request_only' | 'sink_observed';
}

export interface SinkCorrelationResult {
  readonly status: 'no_match' | 'request_only' | 'correlated';
  readonly findings: readonly CorrelatedFinding[];
  readonly observerResult?: InstrumentationResult;
}

function sinkKind(observation: SinkObservation): SinkKind {
  if ('operation' in observation && 'parameterized' in observation) return 'sql';
  if ('resolvedAddressClass' in observation) return 'outboundHttp';
  if ('traversalSegments' in observation) return 'filesystem';
  if ('shellUsed' in observation) return 'command';
  return 'authorization';
}

function matchesSink(finding: DetectionFinding, sink: SinkKind): boolean {
  if (sink === 'sql') return finding.ruleId === 'input.sql_injection_indicator';
  if (sink === 'filesystem') return finding.ruleId === 'input.path_traversal_indicator';
  if (sink === 'outboundHttp') return finding.ruleId === 'input.xss_indicator';
  if (sink === 'command') return finding.ruleId === 'input.sql_injection_indicator';
  return finding.category === 'authorization';
}

export function correlateSinkObservation(
  detection: DetectionResult,
  observation: SinkObservation,
  observerResult?: InstrumentationResult,
): SinkCorrelationResult {
  const kind = sinkKind(observation);
  const sameRequest =
    detection.correlationId !== undefined && detection.correlationId === observation.correlationId;
  const observerDelivered = observerResult?.delivered ?? true;
  const matching =
    sameRequest && observerDelivered
      ? detection.findings.filter((finding) => matchesSink(finding, kind))
      : [];
  if (matching.length === 0) {
    return {
      status: detection.findings.length === 0 ? 'no_match' : 'request_only',
      findings: detection.findings.map((requestFinding) => ({
        status: 'request_indicator',
        requestFinding,
        sink: kind,
        correlationId: observation.correlationId,
        confidence: 'request_only',
      })),
      ...(observerResult === undefined ? {} : { observerResult }),
    };
  }

  return {
    status: 'correlated',
    findings: matching.map((requestFinding) => ({
      status: 'correlated_exploitability',
      requestFinding,
      sink: kind,
      correlationId: observation.correlationId,
      confidence: 'sink_observed',
    })),
    ...(observerResult === undefined ? {} : { observerResult }),
  };
}
