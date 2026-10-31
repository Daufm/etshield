import type { ParserAdapter } from './types.js';

export const queryParser: ParserAdapter<unknown> = {
  id: 'query',
  parse(input: unknown) {
    return { ...(input === undefined ? {} : { value: input }), errors: [] };
  },
};
