import { describe, expect, it } from 'vitest';
import { InMemoryRevocationStore } from '../src/index';

describe('InMemoryRevocationStore', () => {
  it('revokes by token id', async () => {
    const store = new InMemoryRevocationStore();
    expect(await store.isRevoked('jti_1')).toBe(false);
    await store.revoke('jti_1');
    expect(await store.isRevoked('jti_1')).toBe(true);
  });

  it('revokes a whole subject by epoch', async () => {
    const store = new InMemoryRevocationStore();
    await store.revokeSubject('principal_agent_01', '2026-06-04T12:10:00.000Z');

    expect(await store.isRevoked('jti_1', 'principal_agent_01', '2026-06-04T12:00:00.000Z')).toBe(
      true,
    );
    expect(await store.isRevoked('jti_2', 'principal_agent_01', '2026-06-04T12:20:00.000Z')).toBe(
      false,
    );
  });
});
