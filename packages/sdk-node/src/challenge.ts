import type { Request, Response } from 'express';

export interface ChallengeAdapter {
  challenge(
    request: {
      readonly reason: string;
      readonly retryAfterSeconds?: number;
    },
    response: Response,
    expressRequest: Request,
  ): Promise<{ readonly handled: boolean }>;
}
