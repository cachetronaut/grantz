import type { Jti, PrincipalId, RevocationStore } from '@grantz/core';
import { isStateRevoked, revokeState } from '@grantz/core';
import type { StoreDriver, Transaction } from 'dockbay';
import { createPostgresDriver, type PostgresStoreDriver } from 'dockbay/postgres';
import type { Pool } from 'pg';

const REVOKED_JTIS = 'revoked_jtis';
const SUBJECT_EPOCHS = 'subject_epochs';

export interface PostgresRevocationStoreOptions {
  readonly table?: string;
}

export class DriverRevocationStore implements RevocationStore {
  constructor(private readonly driver: StoreDriver | Transaction) {}

  withTransaction(transaction: Transaction): DriverRevocationStore {
    return new DriverRevocationStore(transaction);
  }

  async isRevoked(jti: Jti, subject?: PrincipalId, issuedAt?: string): Promise<boolean> {
    return this.transaction(async (txn) => {
      if (
        (await isStateRevoked(jti, txn)) ||
        (await txn.get(REVOKED_JTIS, { jti })) !== undefined
      ) {
        return true;
      }
      if (subject === undefined || issuedAt === undefined) {
        return false;
      }
      const row = await txn.get(SUBJECT_EPOCHS, { subject });
      if (row === undefined || typeof row.revokedAt !== 'string') {
        return false;
      }
      return Date.parse(issuedAt) <= Date.parse(row.revokedAt);
    });
  }

  async revoke(jti: Jti): Promise<void> {
    await this.transaction(async (txn) => {
      await revokeState(jti, txn);
      await txn.upsert(REVOKED_JTIS, { jti }, { jti });
    });
  }

  async revokeSubject(subject: PrincipalId, revokedAt: string): Promise<void> {
    await this.transaction((txn) =>
      txn.upsert(SUBJECT_EPOCHS, { subject }, { subject, revokedAt }),
    );
  }

  async close(): Promise<void> {
    if ('close' in this.driver) {
      await this.driver.close();
    }
  }

  private transaction<T>(work: (transaction: Transaction) => Promise<T>): Promise<T> {
    return 'transaction' in this.driver ? this.driver.transaction(work) : work(this.driver);
  }
}

export class PostgresRevocationStore extends DriverRevocationStore {
  readonly postgresDriver: PostgresStoreDriver;

  constructor(pool: Pool, options: PostgresRevocationStoreOptions = {}) {
    const driver = createPostgresDriver(pool, { table: options.table });
    super(driver);
    this.postgresDriver = driver;
  }
}
