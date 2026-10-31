const MAX_KEY_PART_LENGTH = 256;

export function boundedKeyPart(value: string): string {
  return value.slice(0, MAX_KEY_PART_LENGTH);
}

export function encodeCounterKey(
  ruleId: string,
  dimensions: readonly (readonly [string, string])[],
): string {
  const parts = [ruleId, ...dimensions.flatMap(([name, value]) => [name, value])];
  return parts
    .map((part) => {
      const bounded = boundedKeyPart(part);
      return `${bounded.length}:${bounded}`;
    })
    .join('');
}
