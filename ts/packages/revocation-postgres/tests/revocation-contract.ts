import { describe, expect, it } from 'vitest';

interface RevocationStoreUnderTest {
  isRevoked(jti: string, subject?: string, issuedAt?: string): Promise<boolean>;
  revoke(jti: string): Promise<void>;
  revokeSubject(subject: string, revokedAt: string): Promise<void>;
  close(): Promise<void>;
}

export function describeRevocationStore(
  label: string,
  createStore: () => RevocationStoreUnderTest,
): void {
  describe(label, () => {
    it('revokes by token id', async () => {
      const store = createStore();
      try {
        expect(await store.isRevoked('jti_1')).toBe(false);
        await store.revoke('jti_1');
        expect(await store.isRevoked('jti_1')).toBe(true);
      } finally {
        await store.close();
      }
    });

    it('revokes a whole subject by epoch', async () => {
      const store = createStore();
      try {
        await store.revokeSubject('principal_agent_01', '2026-06-04T12:10:00.000Z');
        expect(
          await store.isRevoked('jti_1', 'principal_agent_01', '2026-06-04T12:00:00.000Z'),
        ).toBe(true);
        expect(
          await store.isRevoked('jti_2', 'principal_agent_01', '2026-06-04T12:20:00.000Z'),
        ).toBe(false);
      } finally {
        await store.close();
      }
    });
  });
}
