import type { AuthorizationFailureCode } from './types.js';

export class AttenuationError extends Error {
  override readonly name = 'AttenuationError';
}

export class GrantError extends Error {
  override readonly name = 'GrantError';

  constructor(
    readonly code: AuthorizationFailureCode | 'duplicate_id' | 'not_single_use',
    message: string,
  ) {
    super(message);
  }
}
