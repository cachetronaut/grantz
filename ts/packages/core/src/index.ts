export { canonicalize } from './canonical.js';
export { composeConstraints } from './constraints.js';
export { attenuate, authorize, consume, mint, revoke, verify } from './core.js';
export { AttenuationError, GrantError } from './errors.js';
export { covers } from './scope.js';
export type { GrantStore, GrantTransaction } from './state.js';
export { isStateRevoked, revokeState } from './state.js';
export type {
  AuthorizationDecision,
  AuthorizationFailureCode,
  AuthorizationRequest,
  ClockOptions,
  ConstraintValue,
  DelegationId,
  Grant,
  GrantOptions,
  Jti,
  MintOptions,
  Narrowing,
  PrincipalId,
  RevocationStore,
  RunId,
  Scope,
  Signer,
  TaskId,
  TokenClaims,
  Verifier,
  VerifyFailureCode,
  VerifyResult,
} from './types.js';
