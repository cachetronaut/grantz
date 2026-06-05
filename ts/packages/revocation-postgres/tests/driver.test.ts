import { createInMemoryDriver } from '../../../../../dockbay/ts/packages/memory/src/index.js';
import { DriverRevocationStore } from '../src/index.js';
import { describeRevocationStore } from './revocation-contract.js';

describeRevocationStore(
  'DriverRevocationStore',
  () => new DriverRevocationStore(createInMemoryDriver()),
);
