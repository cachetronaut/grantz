export { canonicalize } from './canonical.js';
export { composeConstraints } from './constraints.js';
export { attenuate, authorize, mint, verify } from './core.js';
export { AttenuationError } from './errors.js';
export { covers } from './scope.js';
export type {
  AuthorizationDecision,
  AuthorizationRequest,
  ConstraintValue,
  DelegationId,
  Grant,
  Jti,
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
