import { createHash } from 'node:crypto';

const MAX_EVENT_ROUTE_LENGTH = 512;
const ROUTE_PREFIX_LENGTH = 480;

export function sanitizeEventRoute(path: string): string {
  const original = path;
  const sanitized = path
    .replace(/\/+/g, '/')
    .split('')
    .map((character) => {
      const code = character.codePointAt(0) ?? 0;
      return character === '?' ||
        character === '#' ||
        code <= 0x1f ||
        code === 0x7f
        ? '_'
        : character;
    })
    .join('');
  if (sanitized.length === 0) return '/';
  if (sanitized.length <= ROUTE_PREFIX_LENGTH) return sanitized;
  const digest = createHash('sha256').update(original).digest('hex').slice(0, 12);
  return `${sanitized.slice(0, ROUTE_PREFIX_LENGTH)}~${digest}`.slice(0, MAX_EVENT_ROUTE_LENGTH);
}
