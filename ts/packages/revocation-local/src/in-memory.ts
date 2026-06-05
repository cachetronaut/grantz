import type { Jti, PrincipalId, RevocationStore } from '@grantz/core';

export class InMemoryRevocationStore implements RevocationStore {
  private readonly revoked = new Set<Jti>();
  private readonly subjectEpochs = new Map<PrincipalId, string>();

  async isRevoked(jti: Jti, subject?: PrincipalId, issuedAt?: string): Promise<boolean> {
    if (this.revoked.has(jti)) {
      return true;
    }
    if (subject === undefined || issuedAt === undefined) {
      return false;
    }
    const epoch = this.subjectEpochs.get(subject);
    return epoch !== undefined && Date.parse(issuedAt) <= Date.parse(epoch);
  }

  async revoke(jti: Jti): Promise<void> {
    this.revoked.add(jti);
  }

  async revokeSubject(subject: PrincipalId, revokedAt: string): Promise<void> {
    this.subjectEpochs.set(subject, revokedAt);
  }
}
