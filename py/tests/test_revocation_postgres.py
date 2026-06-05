from __future__ import annotations

import asyncio
import os
import uuid
from typing import cast

import pytest
from dockbay import create_in_memory_driver
from psycopg import AsyncConnection, sql
from psycopg_pool import AsyncConnectionPool

from grantz import DriverRevocationStore, InMemoryRevocationStore, PostgresRevocationStore


async def _assert_revocation_contract(store) -> None:
    assert not await store.is_revoked("jti_1")
    await store.revoke("jti_1")
    assert await store.is_revoked("jti_1")

    await store.revoke_subject("principal_agent_01", "2026-06-04T12:10:00.000Z")
    assert await store.is_revoked("jti_2", "principal_agent_01", "2026-06-04T12:00:00.000Z")
    assert not await store.is_revoked("jti_3", "principal_agent_01", "2026-06-04T12:20:00.000Z")


@pytest.mark.asyncio
async def test_in_memory_revocation_store_revokes_subject_by_epoch() -> None:
    await _assert_revocation_contract(InMemoryRevocationStore())


@pytest.mark.asyncio
async def test_driver_revocation_store_preserves_revocation_semantics() -> None:
    store = DriverRevocationStore(create_in_memory_driver())
    try:
        await _assert_revocation_contract(store)
    finally:
        await store.close()


POSTGRES_URL = os.environ.get("GRANTZ_TEST_POSTGRES_URL")


@pytest.mark.skipif(POSTGRES_URL is None, reason="set GRANTZ_TEST_POSTGRES_URL")
def test_postgres_revocation_store_preserves_revocation_semantics() -> None:
    table = f"grantz_test_{uuid.uuid4().hex}"

    async def scenario() -> None:
        url = cast(str, POSTGRES_URL)
        pool = AsyncConnectionPool(url, open=False)
        await pool.open()
        store = PostgresRevocationStore(pool, table=table)
        try:
            await _assert_revocation_contract(store)
        finally:
            async with await AsyncConnection.connect(url) as conn:
                await conn.execute(
                    sql.SQL("DROP TABLE IF EXISTS {table}").format(table=sql.Identifier(table))
                )
                await conn.commit()
            await store.close()

    asyncio.run(scenario())
