import { canonicalize } from './canonical.js';
import { composeConstraints } from './constraints.js';
import { AttenuationError, GrantError } from './errors.js';
import { covers } from './scope.js';
import { consumeIssued, recordIssued, revokeState, stateFailure } from './state.js';
import type {
  AuthorizationDecision,
  AuthorizationFailureCode,
  AuthorizationRequest,
  Grant,
  GrantOptions,
  MintOptions,
  Narrowing,
  Signer,
  TokenClaims,
  Verifier,
  VerifyFailureCode,
  VerifyResult,
} from './types.js';
import { clockInstant, parseInstant, validateDates, validityFailure } from './validity.js';

export async function mint(
  grant: Grant,
  signer: Signer,
  options: MintOptions = {},
): Promise<string> {
  const claims: TokenClaims = {
    ...grant,
    id: options.id ?? globalThis.crypto.randomUUID(),
    depth: 0,
    issuedAt: new Date(clockInstant(options)).toISOString(),
  };
  validateDates(claims);
  const token = await signer.sign(canonicalize(claims));
  await recordIssued(claims, options.store);
  return token;
}

export async function verify(
  token: string,
  verifier: Verifier,
  options: GrantOptions = {},
): Promise<VerifyResult> {
  let verified: { payload: string; keyId: string };
  try {
    verified = await verifier.verify(token);
  } catch (error) {
    return { ok: false, code: 'bad_sig', reason: errorMessage(error) };
  }
  let claims: unknown;
  try {
    claims = JSON.parse(verified.payload);
  } catch {
    return { ok: false, code: 'malformed', reason: 'Token payload is not JSON' };
  }
  if (!isClaimsShape(claims)) {
    return { ok: false, code: 'malformed', reason: 'Token claims are malformed' };
  }
  const code = await claimsFailure(claims, options);
  if (code !== undefined) {
    return { ok: false, code, reason: failureMessage(code) };
  }
  return { ok: true, claims, keyId: verified.keyId };
}

export async function attenuate(
  parentToken: string,
  narrowing: Narrowing,
  signer: Signer,
  verifier: Verifier,
  options: MintOptions = {},
): Promise<string> {
  const now = new Date(clockInstant(options)).toISOString();
  const verified = await verify(parentToken, verifier, { ...options, now });
  if (!verified.ok) {
    throw new AttenuationError(`Cannot attenuate unverifiable parent: ${verified.code}`);
  }
  const parent = verified.claims;
  if (parent.singleUse === true) {
    throw new AttenuationError('Single-use grants cannot be attenuated');
  }
  const childScopes = narrowing.scopes ?? parent.scopes;
  if (
    !childScopes.every((scope) => parent.scopes.some((parentScope) => covers(parentScope, scope)))
  ) {
    throw new AttenuationError('Child scopes must be covered by parent scopes');
  }
  const childExpiresAt = narrowing.expiresAt ?? parent.expiresAt;
  if (parseInstant(childExpiresAt) > parseInstant(parent.expiresAt)) {
    throw new AttenuationError('Child expiry cannot exceed parent expiry');
  }
  const notBefore = narrowing.notBefore ?? parent.notBefore;
  if (
    notBefore !== undefined &&
    parent.notBefore !== undefined &&
    parseInstant(notBefore) < parseInstant(parent.notBefore)
  ) {
    throw new AttenuationError('Child activation cannot precede parent activation');
  }
  const claims: TokenClaims = {
    issuer: parent.issuer,
    subject: narrowing.subject ?? parent.subject,
    audience: narrowing.audience ?? parent.audience,
    actAs: narrowing.actAs ?? parent.actAs,
    scopes: childScopes,
    constraints: composeConstraints(parent.constraints, narrowing.constraints),
    binding: composeBinding(parent.binding, narrowing.binding),
    singleUse: narrowing.singleUse,
    notBefore,
    expiresAt: childExpiresAt,
    id: options.id ?? globalThis.crypto.randomUUID(),
    parentId: parent.id,
    depth: parent.depth + 1,
    issuedAt: now,
  };
  validateDates(claims);
  const token = await signer.sign(canonicalize(claims));
  await recordIssued(claims, options.store);
  return token;
}

export async function authorize(
  claims: TokenClaims,
  request: AuthorizationRequest,
  options: GrantOptions = {},
): Promise<AuthorizationDecision> {
  if (!isClaimsShape(claims)) {
    return denied('malformed');
  }
  if (request.principal !== claims.subject) {
    return denied('subject');
  }
  const code = await claimsFailure(claims, options);
  if (code !== undefined) {
    return denied(code);
  }
  if (!claims.scopes.some((scope) => covers(scope, request.scope))) {
    return denied('scope');
  }
  if (!bindingMatches(claims.binding, request.context)) {
    return denied('binding');
  }
  return { ok: true, constraints: claims.constraints ?? {} };
}

export async function consume(
  claims: TokenClaims,
  request: AuthorizationRequest,
  options: GrantOptions = {},
): Promise<Extract<AuthorizationDecision, { ok: true }>> {
  const decision = await authorize(claims, request, options);
  if (!decision.ok) {
    throw decision.error;
  }
  if (claims.singleUse !== true) {
    throw new GrantError('not_single_use', 'Grant is not single-use');
  }
  await consumeIssued(claims, options.store);
  return decision;
}

export async function revoke(id: string, options: GrantOptions = {}): Promise<void> {
  await revokeState(id, options.store);
  await options.revocation?.revoke(id);
}

async function claimsFailure(
  claims: TokenClaims,
  options: GrantOptions,
): Promise<VerifyFailureCode | undefined> {
  const validity = validityFailure(claims, options);
  if (validity !== undefined) {
    return validity;
  }
  if (options.audience !== undefined && claims.audience !== options.audience) {
    return 'wrong_audience';
  }
  if (await options.revocation?.isRevoked(claims.id, claims.subject, claims.issuedAt)) {
    return 'revoked';
  }
  return stateFailure(claims, options.store);
}

function denied(reason: AuthorizationFailureCode): AuthorizationDecision {
  return { ok: false, reason, error: new GrantError(reason, failureMessage(reason)) };
}

function failureMessage(code: AuthorizationFailureCode): string {
  return `Grant rejected: ${code}`;
}

function composeBinding(parent: Grant['binding'], child: Grant['binding']): Grant['binding'] {
  if (child === undefined) {
    return parent;
  }
  for (const key of ['taskId', 'delegationId', 'runId'] as const) {
    if (parent?.[key] !== undefined && child[key] !== parent[key]) {
      throw new AttenuationError(`Child binding ${key} cannot differ from parent`);
    }
  }
  return { ...parent, ...child };
}

function bindingMatches(
  binding: Grant['binding'],
  context: AuthorizationRequest['context'],
): boolean {
  if (binding === undefined) {
    return true;
  }
  return (
    (binding.taskId === undefined || binding.taskId === context?.taskId) &&
    (binding.delegationId === undefined || binding.delegationId === context?.delegationId) &&
    (binding.runId === undefined || binding.runId === context?.runId)
  );
}

function isClaimsShape(value: unknown): value is TokenClaims {
  if (!isRecord(value)) {
    return false;
  }
  const binding = value.binding;
  return (
    typeof value.id === 'string' &&
    typeof value.issuer === 'string' &&
    typeof value.subject === 'string' &&
    Array.isArray(value.scopes) &&
    value.scopes.every(
      (scope: unknown) =>
        isRecord(scope) && typeof scope.action === 'string' && typeof scope.resource === 'string',
    ) &&
    Number.isInteger(value.depth) &&
    Number(value.depth) >= 0 &&
    typeof value.issuedAt === 'string' &&
    typeof value.expiresAt === 'string' &&
    (value.notBefore === undefined || typeof value.notBefore === 'string') &&
    (value.singleUse === undefined || typeof value.singleUse === 'boolean') &&
    (binding === undefined ||
      (isRecord(binding) &&
        ['taskId', 'delegationId', 'runId'].every(
          (key) => binding[key] === undefined || typeof binding[key] === 'string',
        )))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Signature verification failed';
}
