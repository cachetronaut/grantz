export type PrincipalId = string;
export type TaskId = string;
export type DelegationId = string;
export type RunId = string;
export type Jti = string;

export interface Scope {
  readonly action: string;
  readonly resource: string;
  readonly qualifier?: string | Readonly<Record<string, unknown>>;
}

export type ConstraintValue = number | boolean | string | readonly string[];

export interface Grant {
  readonly issuer: string;
  readonly subject: PrincipalId;
  readonly audience?: string;
  readonly actAs?: PrincipalId;
  readonly scopes: readonly Scope[];
  readonly constraints?: Readonly<Record<string, ConstraintValue>>;
  readonly binding?: {
    readonly taskId?: TaskId;
    readonly delegationId?: DelegationId;
    readonly runId?: RunId;
  };
  readonly notBefore?: string;
  readonly expiresAt: string;
}

export interface TokenClaims extends Grant {
  readonly id: Jti;
  readonly parentId?: Jti;
  readonly depth: number;
  readonly issuedAt: string;
}

export interface Narrowing {
  readonly subject?: PrincipalId;
  readonly audience?: string;
  readonly actAs?: PrincipalId;
  readonly scopes?: readonly Scope[];
  readonly constraints?: Readonly<Record<string, ConstraintValue>>;
  readonly binding?: Grant['binding'];
  readonly notBefore?: string;
  readonly expiresAt?: string;
}

export interface Signer {
  readonly keyId: string;
  sign(payload: string): Promise<string>;
}

export interface Verifier {
  verify(token: string): Promise<{ payload: string; keyId: string }>;
}

export interface RevocationStore {
  isRevoked(jti: Jti, subject?: PrincipalId, issuedAt?: string): Promise<boolean>;
  revoke(jti: Jti): Promise<void>;
}

export type VerifyFailureCode =
  | 'bad_sig'
  | 'expired'
  | 'not_yet'
  | 'wrong_audience'
  | 'revoked'
  | 'malformed';

export type VerifyResult =
  | { readonly ok: true; readonly claims: TokenClaims; readonly keyId: string }
  | { readonly ok: false; readonly code: VerifyFailureCode; readonly reason: string };

export interface AuthorizationRequest {
  readonly scope: Scope;
  readonly context?: {
    readonly taskId?: TaskId;
    readonly delegationId?: DelegationId;
    readonly runId?: RunId;
  };
}

export type AuthorizationDecision =
  | {
      readonly ok: true;
      readonly constraints: Readonly<Record<string, ConstraintValue>>;
    }
  | {
      readonly ok: false;
      readonly reason: 'scope' | 'binding';
    };
