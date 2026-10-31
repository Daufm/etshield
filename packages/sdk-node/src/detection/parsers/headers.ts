import type { ParserAdapter } from './types.js';

const MAX_HEADER_VALUE_LENGTH = 256;
const ALLOWED_HEADERS = new Set(['accept-language', 'content-type', 'user-agent']);

export type SanitizedHeaders = Readonly<Record<string, string>>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export const headersParser: ParserAdapter<SanitizedHeaders> = {
  id: 'headers',
  parse(input: unknown) {
    if (!isRecord(input)) {
      return {
        errors:
          input === undefined
            ? []
            : [
                {
                  code: 'invalid_input',
                  message: 'Headers must be a record.',
                },
              ],
      };
    }

    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(input)) {
      const normalizedKey = key.toLowerCase();
      if (!ALLOWED_HEADERS.has(normalizedKey) || typeof value !== 'string') continue;
      headers[normalizedKey] = value.slice(0, MAX_HEADER_VALUE_LENGTH);
    }
    return { value: headers, errors: [] };
  },
};
