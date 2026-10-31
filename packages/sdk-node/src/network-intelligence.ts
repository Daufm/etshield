import type { RiskSignal } from '@ethioshield/security-contracts';

export interface NetworkIntelligenceResolver {
  resolve(ip: string): Promise<RiskSignal | undefined>;
  close?(): Promise<void> | void;
}

export async function resolveNetworkRisk(
  resolver: NetworkIntelligenceResolver | undefined,
  ip: string | undefined,
): Promise<RiskSignal | undefined> {
  if (resolver === undefined || ip === undefined) return undefined;
  try {
    const signal = await resolver.resolve(ip);
    if (signal === undefined || Date.parse(signal.expiresAt) <= Date.now()) return undefined;
    if (signal.confidence < 0 || signal.confidence > 1) return undefined;
    return signal;
  } catch {
    return undefined;
  }
}
