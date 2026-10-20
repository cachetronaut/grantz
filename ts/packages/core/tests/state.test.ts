import { createInMemoryDriver } from 'dockbay/memory';
import { expect, it } from 'vitest';
import { authorize, consume, GrantError, mint, revoke, type Signer, verify } from '../src/index.js';

const now = () => new Date('2026-10-20T12:00:00Z');
const scope = { action: 'read', resource: 'record' };
const grant = {
  issuer: 'issuer',
  subject: 'recipient',
  scopes: [scope],
  expiresAt: '2026-10-20T13:00:00Z',
  singleUse: true,
};
const request = { principal: grant.subject, scope };
const signer: Signer = {
  keyId: 'test',
  async sign(payload) {
    return payload;
  },
};
const verifier = {
  async verify(payload: string) {
    return { payload, keyId: 'test' };
  },
};

async function issued() {
  const store = createInMemoryDriver();
  const options = { store, now };
  const token = await mint(grant, signer, options);
  const result = await verify(token, verifier, options);
  if (!result.ok) throw new Error(result.reason);
  return { options, claims: result.claims, token };
}

it('consumes once and rejects a replay with a typed error', async () => {
  const { options, claims } = await issued();
  await expect(consume(claims, request, options)).resolves.toMatchObject({ ok: true });
  await expect(consume(claims, request, options)).rejects.toBeInstanceOf(GrantError);
  await expect(consume(claims, request, options)).rejects.toMatchObject({ code: 'consumed' });
});

it('allows exactly one concurrent consumer of the shared memory store', async () => {
  const { options, claims } = await issued();
  const results = await Promise.all(
    Array.from({ length: 8 }, async () => {
      try {
        await consume(claims, request, options);
        return 'consumed';
      } catch (error) {
        expect(error).toBeInstanceOf(GrantError);
        expect(error).toMatchObject({ code: 'consumed' });
        return 'rejected';
      }
    }),
  );
  expect(results.filter((result) => result === 'consumed')).toHaveLength(1);
});

it('checks persisted revocation even with claims verified before revoking', async () => {
  const { options, claims, token } = await issued();
  await options.store.transaction((transaction) => revoke(claims.id, { store: transaction }));
  await expect(authorize(claims, request, options)).resolves.toMatchObject({
    ok: false,
    reason: 'revoked',
    error: expect.any(GrantError),
  });
  await expect(verify(token, verifier, options)).resolves.toMatchObject({
    ok: false,
    code: 'revoked',
  });
});

it('rejects a different presenting principal without consuming the grant', async () => {
  const { options, claims } = await issued();
  await expect(
    authorize(claims, { ...request, principal: 'other' }, options),
  ).resolves.toMatchObject({ ok: false, reason: 'subject', error: expect.any(GrantError) });
  await expect(consume(claims, request, options)).resolves.toMatchObject({ ok: true });
});

it('rejects malformed instants and compares validity against an injected clock', async () => {
  for (const expiresAt of [
    'tomorrow',
    '10/20/2026',
    '2026-02-30T00:00:00Z',
    '2026-10-20T12:00:00',
  ]) {
    await expect(mint({ ...grant, expiresAt }, signer, { now })).rejects.toMatchObject({
      code: 'invalid_date',
    });
  }
  const store = createInMemoryDriver();
  const token = await mint(
    { ...grant, notBefore: '2026-10-20T08:01:00-04:00', expiresAt: '2026-10-20T09:00:00-04:00' },
    signer,
    { store, now },
  );
  await expect(verify(token, verifier, { store, now })).resolves.toMatchObject({
    ok: false,
    code: 'not_yet',
  });
  await expect(
    verify(token, verifier, { store, now: () => new Date('2026-10-20T12:30:00Z') }),
  ).resolves.toMatchObject({ ok: true });
  await expect(
    verify(token, verifier, { store, now: () => new Date('2026-10-20T13:00:00Z') }),
  ).resolves.toMatchObject({ ok: false, code: 'expired' });
  const malformed = JSON.stringify({ ...JSON.parse(token), expiresAt: 'not-a-date' });
  await expect(verify(malformed, verifier, { store, now })).resolves.toMatchObject({
    ok: false,
    code: 'invalid_date',
  });
});
