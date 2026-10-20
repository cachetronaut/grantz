import { consume, mint, verify } from '@grantz/core';
import { createInMemoryDriver } from 'dockbay/memory';
import { expect, it } from 'vitest';
import { DriverRevocationStore } from '../src/index.js';
import { describeRevocationStore } from './revocation-contract.js';

describeRevocationStore(
  'DriverRevocationStore',
  () => new DriverRevocationStore(createInMemoryDriver()),
);

it('consumes with revocation bound to the active transaction', async () => {
  const store = createInMemoryDriver();
  const revocation = new DriverRevocationStore(store);
  const now = () => new Date('2026-10-20T12:00:00Z');
  const scope = { action: 'read', resource: 'record' };
  const token = await mint(
    {
      issuer: 'issuer',
      subject: 'recipient',
      scopes: [scope],
      singleUse: true,
      expiresAt: '2026-10-20T13:00:00Z',
    },
    {
      keyId: 'test',
      async sign(payload) {
        return payload;
      },
    },
    { store, now },
  );
  const result = await verify(
    token,
    {
      async verify(payload) {
        return { payload, keyId: 'test' };
      },
    },
    { store, now },
  );
  if (!result.ok) throw new Error(result.reason);
  await store.transaction(async (transaction) => {
    const bound = revocation.withTransaction(transaction);
    await expect(
      consume(
        result.claims,
        { principal: 'recipient', scope },
        { store: transaction, revocation: bound, now },
      ),
    ).resolves.toMatchObject({ ok: true });
    await bound.revoke(result.claims.id);
    expect(await bound.isRevoked(result.claims.id)).toBe(true);
    await bound.close();
  });
  await store.close();
});
