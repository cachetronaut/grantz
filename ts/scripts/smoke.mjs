import assert from 'node:assert/strict';
import { InMemoryConvexOperationHost } from 'dockbay/convex';
import { createInMemoryDriver } from 'dockbay/memory';
import { authorize, consume, GrantError, mint, revoke, verify } from '../dist/index.js';
import { ConvexRevocationStore, createRevocationOperations } from '../dist/revocation-convex.js';
import { InMemoryRevocationStore } from '../dist/revocation-local.js';
import { DriverRevocationStore, PostgresRevocationStore } from '../dist/revocation-postgres.js';
import {
  Ed25519LocalSigner,
  Ed25519LocalVerifier,
  generateLocalKeyPair,
} from '../dist/signer-local.js';

const key = generateLocalKeyPair('smoke');
const signer = new Ed25519LocalSigner(key);
const verifier = new Ed25519LocalVerifier([key]);
const now = () => new Date('2026-10-20T12:00:00Z');
const scope = { action: 'read', resource: 'record' };
const request = { principal: 'recipient', scope };
const grant = {
  issuer: 'issuer',
  subject: request.principal,
  scopes: [scope],
  singleUse: true,
  expiresAt: '2026-10-20T13:00:00.000000Z',
};
const token = await mint(grant, signer, { now });
const verified = await verify(token, verifier, { now });
assert(verified.ok);
assert.match(
  verified.claims.id,
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
);
assert((await authorize(verified.claims, request, { now })).ok);
assert((await consume(verified.claims, request, { now })).ok);
await assert.rejects(
  consume(verified.claims, request, { now }),
  (error) => error instanceof GrantError && error.code === 'consumed',
);

const store = createInMemoryDriver();
const options = { store, now };
const sharedToken = await mint(grant, signer, options);
const shared = await verify(sharedToken, verifier, options);
assert(shared.ok);
const wrongPrincipal = await authorize(shared.claims, { ...request, principal: 'other' }, options);
assert(!wrongPrincipal.ok && wrongPrincipal.error.code === 'subject');
const results = await Promise.all(
  Array.from({ length: 8 }, async () => {
    try {
      await consume(shared.claims, request, {
        ...options,
        store: { transaction: (work) => store.transaction(work) },
      });
      return true;
    } catch (error) {
      assert(error instanceof GrantError && error.code === 'consumed');
      return false;
    }
  }),
);
assert.equal(results.filter(Boolean).length, 1);

const reusable = await mint({ ...grant, singleUse: false }, signer, options);
const claims = await verify(reusable, verifier, options);
assert(claims.ok);
const revocation = new DriverRevocationStore(store);
await store.transaction(async (transaction) => {
  const bound = revocation.withTransaction(transaction);
  const transactionOptions = { ...options, store: transaction, revocation: bound };
  assert((await authorize(claims.claims, request, transactionOptions)).ok);
  await revoke(claims.claims.id, transactionOptions);
});
const denied = await authorize(claims.claims, request, options);
assert(!denied.ok && denied.reason === 'revoked');
const revoked = await verify(reusable, verifier, options);
assert(!revoked.ok && revoked.code === 'revoked');
await revoke(claims.claims.id, options);

await assert.rejects(
  mint({ ...grant, expiresAt: 'October 20, 2026' }, signer, { now }),
  (error) => error instanceof GrantError && error.code === 'invalid_date',
);
const expired = await verify(sharedToken, verifier, {
  ...options,
  now: () => new Date('2026-10-20T13:00:00Z'),
});
assert(!expired.ok && expired.code === 'expired');
const future = await mint({ ...grant, notBefore: '2026-10-20T08:01:00-04:00' }, signer, options);
const inactive = await verify(future, verifier, options);
assert(!inactive.ok && inactive.code === 'not_yet');

const local = new InMemoryRevocationStore();
await local.revoke('local');
assert(await local.isRevoked('local'));
const convex = new ConvexRevocationStore(
  new InMemoryConvexOperationHost(createRevocationOperations()).createDriver(),
);
await convex.revoke('convex');
assert(await convex.isRevoked('convex'));
assert.equal(typeof PostgresRevocationStore, 'function');
await store.close();
process.stdout.write(
  `Grant smoke passed on ${process.versions.bun ? `Bun ${process.versions.bun}` : `Node ${process.versions.node}`}\n`,
);
