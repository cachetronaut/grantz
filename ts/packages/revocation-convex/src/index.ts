import type { Jti, PrincipalId, RevocationStore } from '@grantz/core';
import type {
  ConvexOperationDriver,
  ConvexStoreOperation,
  JsonValue,
} from '../../../../../dockbay/ts/packages/convex/src/index.js';

const REVOKE_JTI = 'revocation.revokeJti';
const REVOKE_SUBJECT = 'revocation.revokeSubject';
const IS_REVOKED = 'revocation.isRevoked';

export interface ConvexRevocationStoreOptions {
  readonly operations?: {
    readonly revokeJti?: string;
    readonly revokeSubject?: string;
    readonly isRevoked?: string;
  };
}

export class ConvexRevocationStore implements RevocationStore {
  private readonly operations: Required<NonNullable<ConvexRevocationStoreOptions['operations']>>;

  constructor(
    private readonly driver: ConvexOperationDriver,
    options: ConvexRevocationStoreOptions = {},
  ) {
    this.operations = {
      revokeJti: options.operations?.revokeJti ?? REVOKE_JTI,
      revokeSubject: options.operations?.revokeSubject ?? REVOKE_SUBJECT,
      isRevoked: options.operations?.isRevoked ?? IS_REVOKED,
    };
  }

  async isRevoked(jti: Jti, subject?: PrincipalId, issuedAt?: string): Promise<boolean> {
    const result = (await this.driver.call(this.operations.isRevoked, {
      jti,
      subject,
      issuedAt,
    } as unknown as JsonValue)) as unknown as { revoked: boolean };
    return result.revoked;
  }

  async revoke(jti: Jti): Promise<void> {
    await this.driver.call(this.operations.revokeJti, { jti });
  }

  async revokeSubject(subject: PrincipalId, revokedAt: string): Promise<void> {
    await this.driver.call(this.operations.revokeSubject, { subject, revokedAt });
  }

  async close(): Promise<void> {}
}

export function createRevocationOperations(): readonly ConvexStoreOperation[] {
  const revokedJtis = new Set<Jti>();
  const subjectEpochs = new Map<PrincipalId, string>();

  return [
    {
      name: REVOKE_JTI,
      kind: 'mutation',
      async run(_ctx, input) {
        const { jti } = input as unknown as { jti: Jti };
        revokedJtis.add(jti);
        return null;
      },
    },
    {
      name: REVOKE_SUBJECT,
      kind: 'mutation',
      async run(_ctx, input) {
        const { subject, revokedAt } = input as unknown as {
          subject: PrincipalId;
          revokedAt: string;
        };
        subjectEpochs.set(subject, revokedAt);
        return null;
      },
    },
    {
      name: IS_REVOKED,
      kind: 'query',
      async run(_ctx, input) {
        const { jti, subject, issuedAt } = input as unknown as {
          jti: Jti;
          subject?: PrincipalId;
          issuedAt?: string;
        };
        if (revokedJtis.has(jti)) {
          return { revoked: true };
        }
        if (subject === undefined || issuedAt === undefined) {
          return { revoked: false };
        }
        const epoch = subjectEpochs.get(subject);
        return {
          revoked: epoch !== undefined && Date.parse(issuedAt) <= Date.parse(epoch),
        } as unknown as JsonValue;
      },
    },
  ];
}
