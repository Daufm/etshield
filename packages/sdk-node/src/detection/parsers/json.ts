import type { ParserAdapter, ParserResult } from './types.js';

const MAX_JSON_BYTES = 1_048_576;

export const jsonParser: ParserAdapter<unknown> & {
  parseText(input: string): ParserResult<unknown>;
} = {
  id: 'json',
  parse(input: unknown) {
    return { ...(input === undefined ? {} : { value: input }), errors: [] };
  },
  parseText(input: string) {
    if (Buffer.byteLength(input, 'utf8') > MAX_JSON_BYTES) {
      return {
        errors: [
          {
            code: 'size_limit',
            message: 'JSON input exceeded the parser size limit.',
          },
        ],
      };
    }
    try {
      return { value: JSON.parse(input) as unknown, errors: [] };
    } catch {
      return {
        errors: [
          {
            code: 'malformed_json',
            message: 'JSON input could not be parsed.',
          },
        ],
      };
    }
  },
};
