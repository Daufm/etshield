import type { DetectionComponent } from '@ethioshield/security-contracts';

export type ParsedComponent = Exclude<DetectionComponent, 'route'>;

export interface ParserError {
  readonly code: 'invalid_input' | 'size_limit' | 'malformed_json';
  readonly message: string;
}

export interface ParserResult<T> {
  readonly value?: T;
  readonly errors: readonly ParserError[];
}

export interface ParserAdapter<T> {
  readonly id: string;
  parse(input: unknown): ParserResult<T>;
}
