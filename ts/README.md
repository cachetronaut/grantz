---
status: active
updated: 2026-10-20
description: TypeScript grant APIs, durable state, validity checks, and runtime support.
keywords: [grantz, typescript, durable-state, single-use, revocation, bun]
---

# Grantz

Scoped, signed grants for Node >= 24 and Bun 1.4. The package is ESM.

## Install

```sh
pnpm add @cachetronaut/grantz
```

## Mint, verify, authorize, and consume

```ts
import { authorize, consume, mint, verify } from '@cachetronaut/grantz';
import {
  Ed25519LocalSigner,
  Ed25519LocalVerifier,
  generateLocalKeyPair,
} from '@cachetronaut/grantz/signer-local';

const keys = generateLocalKeyPair();
const signer = new Ed25519LocalSigner(keys);
const verifier = new Ed25519LocalVerifier([keys]);
const scope = { action: 'read', resource: 'record' };
const options = { now: () => new Date('2026-10-20T12:00:00Z') };
const token = await mint({
  issuer: 'issuer',
  subject: 'recipient',
  scopes: [scope],
  singleUse: true,
  expiresAt: '2026-10-20T13:00:00Z',
}, signer, options);

const verified = await verify(token, verifier, options);
if (!verified.ok) throw new Error(verified.code);
const request = { principal: 'recipient', scope };
const decision = await authorize(verified.claims, request, options);
if (!decision.ok) throw decision.error;
await consume(verified.claims, request, options);
```

Pass only claims returned by a successful `verify` to `authorize` and `consume`. These two functions do not verify signatures. `request.principal` must come from the authenticated presenter. It must equal `claims.subject`; `actAs` does not replace the subject check.

`verify` and `authorize` check validity, audience, revocation, and stored state. `authorize` also checks subject, scopes, and bindings. Both functions are read-only. `consume` repeats authorization and atomically changes a single-use grant from `issued` to `consumed`. Use its successful result as the permission to proceed. Exactly one concurrent consumer succeeds. A second consume throws `GrantError` with `code: 'consumed'`. Reusable grants omit `singleUse` or set it to `false`; consuming one throws `not_single_use`.

Failures from `verify` remain discriminated results with `ok: false`, `code`, and `reason`. Authorization failures have `ok: false`, a typed `reason`, and `error: GrantError`. `consume` throws that error on denial. New state and validity codes include `consumed`, `revoked`, `unknown_grant`, `state_mismatch`, and `invalid_date`. Wrong presenters receive `subject`. Signing and storage failures propagate to the caller.

## Durable state

Without `store`, the module keeps issued, consumed, and revoked records in memory. This default lasts for the process lifetime. Supply the same durable store to every operation to retain state across restarts and share it across processes. Retain the signing and verification keys separately.

`store` accepts a dockbay `StoreDriver` or `Transaction`. Grantz uses the published `dockbay@0.0.0` contracts through type imports and requires atomic `compareAndApply`. A driver opens a transaction for each state operation. A transaction can be supplied directly while it is active.

```ts
import { Pool } from 'pg';
import { createPostgresDriver } from 'dockbay/postgres';
import { revoke } from '@cachetronaut/grantz';

const pool = new Pool();
const store = createPostgresDriver(pool, { table: 'grant_state' });
const options = { store, now: () => new Date() };
// Use these options for mint, verify, authorize, consume, attenuate, and revoke.
await revoke('grant-id', options);
await store.transaction(async (transaction) => {
  await revoke('another-grant-id', { store: transaction });
});
// Close the driver when all grant operations have finished.
await store.close();
```

Grantz stores canonical claims and their status in the `grantz_grants` logical table, keyed by `{ id }`. Minting persists `issued` before returning the signed token. An existing id cannot be issued again, including after consumption or revocation; issuance throws `duplicate_id`. Revocation uses compare-and-apply on the same record, so consumption cannot overwrite it. Revoking an unknown id creates a tombstone. Keep records for as long as their grants can be presented.

Single-use grants require an issued record in the selected store. A missing record returns `unknown_grant`, so changing stores or restarting with the memory default cannot reset single-use grants. Older reusable signed tokens may be verified without an issuance record. Their revocations still require the same store on every verification and authorization call. Grantz never closes a supplied store.

For a memory driver shared by several callers, use `createInMemoryDriver` from `dockbay/memory`. This driver is also process-local.

## Revocation adapters

`revoke(id, options)` persists a revocation in the grant state store. Both `verify` and `authorize` read that store each time, including when the claims were verified before revocation. Revocation is per id; it does not cascade to descendants.

Existing `InMemoryRevocationStore`, `DriverRevocationStore`, `PostgresRevocationStore`, and `ConvexRevocationStore` remain supported through `options.revocation`. Pass the same adapter to `verify`, `authorize`, `consume`, and `attenuate` for its id and subject-epoch checks. Passing it to `revoke` also forwards the revocation to that adapter after persisting the grant-state tombstone. The two writes are separate; retry `revoke` if forwarding fails.

`DriverRevocationStore` also writes the shared grant-state tombstone in its transaction and keeps the existing `revoked_jtis` records. It retains `subject_epochs` for subject-wide revocation. When this adapter and the grant APIs use the same driver, id revocation is visible through the grant state store alone. Subject epochs and other revocation adapters still require `options.revocation`. Checks against a separate adapter are not atomic with consumption. For caller-owned transactions on the same driver, bind the revocation adapter to the active transaction to include its reads and writes without opening a nested transaction:

```ts
import { DriverRevocationStore } from '@cachetronaut/grantz/revocation-postgres';

const revocation = new DriverRevocationStore(store);
await store.transaction(async (transaction) => {
  await consume(verified.claims, request, {
    store: transaction,
    revocation: revocation.withTransaction(transaction),
  });
});
```

`DriverRevocationStore` also accepts a `Transaction` in its constructor. A transaction-bound adapter's `close()` is a no-op. Bind only when the transaction uses the adapter's intended database and table. Keep adapters for different stores unbound.

`createRevocationOperations` and the in-memory Convex operation host retain their existing process-local behavior. A durable Convex revocation adapter requires persistent server operations supplied through its operation driver. The Convex operation driver is not a dockbay `Transaction`; use a transaction-capable driver for single-use state.

Adapter authors can import `isStateRevoked(id, store)` and `revokeState(id, store)` from `@grantz/core` to read and write grant-state tombstones without forwarding to another revocation adapter. Packages that import core declare it as a workspace dependency.

The workspace package `@grantz/revocation-postgres/testing` exports `describeRevocationStore` for the shared revocation contract tests. It requires Vitest 2, declared as an optional peer dependency. Packages using this helper declare `@grantz/revocation-postgres` as a development dependency.

## Ids and validity

Minting and attenuation use `globalThis.crypto.randomUUID()` unless `options.id` is supplied explicitly. Explicit ids must be unique in the store.

`options.now` accepts `() => Date` and defaults to the current time. The existing ISO string option remains supported. `issuedAt`, `notBefore`, and `expiresAt` must use `YYYY-MM-DDTHH:mm:ss[.fraction]Z` or an explicit `±HH:mm` offset, with optional fractional seconds. Sub-millisecond digits are accepted and compared at JavaScript millisecond precision. Invalid calendar dates, date-only strings, local timestamps, and non-ISO strings are rejected with `invalid_date`. Comparisons use epoch milliseconds, so equivalent timezone offsets represent the same instant. `notBefore` is inclusive; `expiresAt` is exclusive.

`attenuate` accepts the same store, clock, audience, and revocation options as verification, plus `id`. Child expiry cannot exceed parent expiry, and child activation cannot precede parent activation. A reusable parent may issue a single-use child with `narrowing.singleUse: true`. A single-use parent cannot be attenuated, because separate children would bypass its one-consumption limit.

## Compatibility changes

- Await `authorize` and provide `request.principal`. Authorization now rechecks time, audience, revocation, and state, and denied results include `GrantError`.
- Replace assumptions about sequential ids with UUIDs. Explicit duplicate ids fail instead of reissuing a grant.
- Use timezone-qualified ISO timestamps. Previously accepted malformed dates now fail.
- Pass the same store and revocation options through all operations. Single-use grants fail closed when their issuance record is absent.
- This entry describes the TypeScript API. Python behavior is unchanged.

## Development

Run from `ts/` with Node 24 and Bun 1.4 installed:

```sh
pnpm install
pnpm check
pnpm typecheck
pnpm test
pnpm build
node scripts/smoke.mjs
bun run scripts/smoke.mjs
```

The smoke script imports every built entry point, uses the Ed25519 signer, and checks single-use consumption, a concurrent race, revocation, subject enforcement, UUIDs, and clock-based validity under both runtimes. Set `GRANTZ_TEST_POSTGRES_URL` to run the existing live Postgres tests; otherwise those two tests skip. The workspace uses npm dockbay exports and needs no sibling checkout.

## License

MIT
