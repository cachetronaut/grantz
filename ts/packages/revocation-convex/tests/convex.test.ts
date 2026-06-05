import { InMemoryConvexOperationHost } from '../../../../../dockbay/ts/packages/convex/src/index.js';
import { describeRevocationStore } from '../../revocation-postgres/tests/revocation-contract.js';
import { ConvexRevocationStore, createRevocationOperations } from '../src/index.js';

describeRevocationStore(
  'ConvexRevocationStore',
  () =>
    new ConvexRevocationStore(
      new InMemoryConvexOperationHost(createRevocationOperations()).createDriver(),
    ),
);
