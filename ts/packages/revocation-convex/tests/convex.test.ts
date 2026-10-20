import { describeRevocationStore } from '@grantz/revocation-postgres/testing';
import { InMemoryConvexOperationHost } from 'dockbay/convex';
import { ConvexRevocationStore, createRevocationOperations } from '../src/index.js';

describeRevocationStore(
  'ConvexRevocationStore',
  () =>
    new ConvexRevocationStore(
      new InMemoryConvexOperationHost(createRevocationOperations()).createDriver(),
    ),
);
