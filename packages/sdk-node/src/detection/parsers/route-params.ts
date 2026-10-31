import type { ParserAdapter } from './types.js';

export const routeParamsParser: ParserAdapter<unknown> = {
  id: 'route_params',
  parse(input: unknown) {
    return { ...(input === undefined ? {} : { value: input }), errors: [] };
  },
};
