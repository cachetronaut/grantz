import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe } from 'vitest';
import { PostgresRevocationStore } from '../src/index.js';
import { describeRevocationStore } from './revocation-contract.js';

const POSTGRES_URL = process.env.GRANTZ_TEST_POSTGRES_URL;

describe.skipIf(POSTGRES_URL === undefined)('PostgresRevocationStore', () => {
  let pool: Pool;
  let table: string;

  beforeAll(() => {
    table = `grantz_test_${randomUUID().replaceAll('-', '_')}`;
    pool = new Pool({ connectionString: POSTGRES_URL });
  });

  afterAll(async () => {
    await pool.query(`DROP TABLE IF EXISTS "${table}"`);
    await pool.end();
  });

  describeRevocationStore(
    'PostgresRevocationStore',
    () => new PostgresRevocationStore(pool, { table }),
  );
});
