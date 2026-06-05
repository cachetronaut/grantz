import { canonicalize } from './canonical.js';
import { composeConstraints } from './constraints.js';
import { AttenuationError } from './errors.js';
import { covers } from './scope.js';
import type {
  AuthorizationDecision,
  AuthorizationRequest,
  Grant,
  Narrowing,
  RevocationStore,
  Signer,
  TokenClaims,
  Verifier,
  VerifyResult,
} from './types.js';

let nextTokenSeq = 1;

export async function mint(
  grant: Grant,
  signer: Signer,
  options: { now?: string; id?: string } = {},
): Promise<string> {
  const claims: TokenClaims = {
    ...grant,
    id: options.id ?? nextJti(),
    depth: 0,
    issuedAt: options.now ?? new Date().toISOString(),
  };
  return signer.sign(canonicalize(claims));
}

export async function verify(
  token: string,
  verifier: Verifier,
  opts: { audience?: string; now?: string; revocation?: RevocationStore } = {},
): Promise<VerifyResult> {
  let verified: { payload: string; keyId: string };
  try {
    verified = await verifier.verify(token);
  } catch (error) {
    return { ok: false, code: 'bad_sig', reason: errorMessage(error) };
  }

  let claims: TokenClaims;
  try {
    claims = JSON.parse(verified.payload) as TokenClaims;
  } catch {
    return { ok: false, code: 'malformed', reason: 'Token payload is not JSON' };
  }

  const now = Date.parse(opts.now ?? new Date().toISOString());
  if (Number.isNaN(now) || !isClaimsShape(claims)) {
    return { ok: false, code: 'malformed', reason: 'Token claims are malformed' };
  }
  if (claims.notBefore !== undefined && now < Date.parse(claims.notBefore)) {
    return { ok: false, code: 'not_yet', reason: 'Token is not active yet' };
  }
  if (now >= Date.parse(claims.expiresAt)) {
    return { ok: false, code: 'expired', reason: 'Token is expired' };
  }
  if (opts.audience !== undefined && claims.audience !== opts.audience) {
    return { ok: false, code: 'wrong_audience', reason: 'Token audience does not match' };
  }
  if (await opts.revocation?.isRevoked(claims.id, claims.subject, claims.issuedAt)) {
    return { ok: false, code: 'revoked', reason: 'Token was revoked' };
  }
  return { ok: true, claims, keyId: verified.keyId };
}

export async function attenuate(
  parentToken: string,
  narrowing: Narrowing,
  signer: Signer,
  verifier: Verifier,
  options: { now?: string; id?: string } = {},
): Promise<string> {
  const verified = await verify(parentToken, verifier, { now: options.now });
  if (!verified.ok) {
    throw new AttenuationError(`Cannot attenuate unverifiable parent: ${verified.code}`);
  }
  const parent = verified.claims;
  const childScopes = narrowing.scopes ?? parent.scopes;
  if (
    !childScopes.every((scope) => parent.scopes.some((parentScope) => covers(parentScope, scope)))
  ) {
    throw new AttenuationError('Child scopes must be covered by parent scopes');
  }
  const childExpiresAt = narrowing.expiresAt ?? parent.expiresAt;
  if (Date.parse(childExpiresAt) > Date.parse(parent.expiresAt)) {
    throw new AttenuationError('Child expiry cannot exceed parent expiry');
  }
  const childBinding = composeBinding(parent.binding, narrowing.binding);
  const claims: TokenClaims = {
    issuer: parent.issuer,
    subject: narrowing.subject ?? parent.subject,
    audience: narrowing.audience ?? parent.audience,
    actAs: narrowing.actAs ?? parent.actAs,
    scopes: childScopes,
    constraints: composeConstraints(parent.constraints, narrowing.constraints),
    binding: childBinding,
    notBefore: narrowing.notBefore ?? parent.notBefore,
    expiresAt: childExpiresAt,
    id: options.id ?? nextJti(),
    parentId: parent.id,
    depth: parent.depth + 1,
    issuedAt: options.now ?? new Date().toISOString(),
  };
  return signer.sign(canonicalize(claims));
}

export function authorize(
  claims: TokenClaims,
  request: AuthorizationRequest,
): AuthorizationDecision {
  if (!claims.scopes.some((scope) => covers(scope, request.scope))) {
    return { ok: false, reason: 'scope' };
  }
  if (!bindingMatches(claims.binding, request.context)) {
    return { ok: false, reason: 'binding' };
  }
  return { ok: true, constraints: claims.constraints ?? {} };
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

function nextJti(): string {
  const id = `jti_${nextTokenSeq}`;
  nextTokenSeq += 1;
  return id;
}

function isClaimsShape(value: TokenClaims): boolean {
  return (
    typeof value.id === 'string' &&
    typeof value.issuer === 'string' &&
    typeof value.subject === 'string' &&
    Array.isArray(value.scopes) &&
    typeof value.depth === 'number' &&
    typeof value.issuedAt === 'string' &&
    typeof value.expiresAt === 'string'
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Signature verification failed';
}
