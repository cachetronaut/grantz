import type { Jti, PrincipalId, RevocationStore } from '@grantz/core';
import type { Pool } from 'pg';
import type { StoreDriver } from '../../../../../dockbay/ts/packages/core/src/index.js';
import {
  createPostgresDriver,
  type PostgresStoreDriver,
} from '../../../../../dockbay/ts/packages/postgres/src/index.js';

const REVOKED_JTIS = 'revoked_jtis';
const SUBJECT_EPOCHS = 'subject_epochs';

export interface PostgresRevocationStoreOptions {
  readonly table?: string;
}

export class DriverRevocationStore implements RevocationStore {
  constructor(private readonly driver: StoreDriver) {}

  async isRevoked(jti: Jti, subject?: PrincipalId, issuedAt?: string): Promise<boolean> {
    return this.driver.transaction(async (txn) => {
      if ((await txn.get(REVOKED_JTIS, { jti })) !== undefined) {
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
    await this.driver.transaction((txn) => txn.upsert(REVOKED_JTIS, { jti }, { jti }));
  }

  async revokeSubject(subject: PrincipalId, revokedAt: string): Promise<void> {
    await this.driver.transaction((txn) =>
      txn.upsert(SUBJECT_EPOCHS, { subject }, { subject, revokedAt }),
    );
  }

  async close(): Promise<void> {
    await this.driver.close();
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
