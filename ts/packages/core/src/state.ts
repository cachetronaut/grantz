import type { Row, StoreDriver, Transaction } from 'dockbay';
import { canonicalize } from './canonical.js';
import { GrantError } from './errors.js';
import type { TokenClaims, VerifyFailureCode } from './types.js';

export type GrantTransaction = Pick<Transaction, 'get' | 'compareAndApply'>;
export type GrantStore = GrantTransaction | Pick<StoreDriver, 'transaction'>;

const TABLE = 'grantz_grants';
const rows = new Map<string, Row>();
const memory: GrantTransaction = {
  async get(table, key) {
    return rows.get(canonicalize({ table, key }));
  },
  async compareAndApply(table, key, expected, next: Row) {
    const id = canonicalize({ table, key });
    if (canonicalize(rows.get(id)) !== canonicalize(expected)) {
      return false;
    }
    rows.set(id, next);
    return true;
  },
};

export function withGrantTransaction<T>(
  store: GrantStore | undefined,
  work: (transaction: GrantTransaction) => Promise<T>,
): Promise<T> {
  const selected = store ?? memory;
  return 'transaction' in selected ? selected.transaction(work) : work(selected);
}

export async function recordIssued(claims: TokenClaims, store?: GrantStore): Promise<void> {
  await withGrantTransaction(store, async (transaction) => {
    if (
      !(await transaction.compareAndApply(TABLE, { id: claims.id }, undefined, {
        status: 'issued',
        claims: canonicalize(claims),
      }))
    ) {
      throw new GrantError('duplicate_id', 'Grant id already exists');
    }
  });
}

export async function stateFailure(
  claims: TokenClaims,
  store?: GrantStore,
): Promise<VerifyFailureCode | undefined> {
  return withGrantTransaction(store, async (transaction) => {
    const row = await transaction.get(TABLE, { id: claims.id });
    if (row?.status === 'revoked') {
      return 'revoked';
    }
    if (row !== undefined && row.claims !== canonicalize(claims)) {
      return 'state_mismatch';
    }
    if (row?.status === 'consumed') {
      return 'consumed';
    }
    if (row === undefined && claims.singleUse === true) {
      return 'unknown_grant';
    }
    return undefined;
  });
}

export async function consumeIssued(claims: TokenClaims, store?: GrantStore): Promise<void> {
  await withGrantTransaction(store, async (transaction) => {
    const expected = { status: 'issued', claims: canonicalize(claims) };
    if (
      !(await transaction.compareAndApply(TABLE, { id: claims.id }, expected, {
        ...expected,
        status: 'consumed',
      }))
    ) {
      const row = await transaction.get(TABLE, { id: claims.id });
      const code = row?.status === 'revoked' ? 'revoked' : 'consumed';
      throw new GrantError(code, 'Grant is no longer available for consumption');
    }
  });
}

export async function revokeState(id: string, store?: GrantStore): Promise<void> {
  await withGrantTransaction(store, async (transaction) => {
    for (;;) {
      const current = await transaction.get(TABLE, { id });
      if (current?.status === 'revoked') {
        return;
      }
      if (
        await transaction.compareAndApply(TABLE, { id }, current, {
          ...current,
          status: 'revoked',
        })
      ) {
        return;
      }
    }
  });
}

export async function isStateRevoked(id: string, store?: GrantStore): Promise<boolean> {
  return withGrantTransaction(
    store,
    async (transaction) => (await transaction.get(TABLE, { id }))?.status === 'revoked',
  );
}
