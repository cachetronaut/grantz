from __future__ import annotations

import pytest
from dockbay import InMemoryConvexOperationHost
from test_revocation_postgres import _assert_revocation_contract

from grantz import ConvexRevocationStore, create_revocation_operations


@pytest.mark.asyncio
async def test_convex_revocation_store_preserves_revocation_semantics() -> None:
    store = ConvexRevocationStore(
        InMemoryConvexOperationHost(create_revocation_operations()).create_driver()
    )
    try:
        await _assert_revocation_contract(store)
    finally:
        await store.close()
