import { InMemoryConvexOperationHost } from 'dockbay/convex';
import { describeRevocationStore } from '../../revocation-postgres/tests/revocation-contract.js';
import { ConvexRevocationStore, createRevocationOperations } from '../src/index.js';

describeRevocationStore(
  'ConvexRevocationStore',
  () =>
    new ConvexRevocationStore(
      new InMemoryConvexOperationHost(createRevocationOperations()).createDriver(),
    ),
);
