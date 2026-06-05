from __future__ import annotations

from dockbay import (
    PostgresStoreDriver,
    PostgresStoreDriverOptions,
    StoreDriver,
    create_postgres_driver,
)
from psycopg_pool import AsyncConnectionPool

REVOKED_JTIS = "revoked_jtis"
SUBJECT_EPOCHS = "subject_epochs"


class DriverRevocationStore:
    def __init__(self, driver: StoreDriver) -> None:
        self._driver = driver

    async def is_revoked(
        self, jti: str, subject: str | None = None, issued_at: str | None = None
    ) -> bool:
        async def work(txn) -> bool:
            if await txn.get(REVOKED_JTIS, {"jti": jti}) is not None:
                return True
            if subject is None or issued_at is None:
                return False
            row = await txn.get(SUBJECT_EPOCHS, {"subject": subject})
            if row is None or not isinstance(row.get("revokedAt"), str):
                return False
            return _parse_ms(issued_at) <= _parse_ms(row["revokedAt"])

        return await self._driver.transaction(work)

    async def revoke(self, jti: str) -> None:
        async def work(txn) -> None:
            await txn.upsert(REVOKED_JTIS, {"jti": jti}, {"jti": jti})

        await self._driver.transaction(work)

    async def revoke_subject(self, subject: str, revoked_at: str) -> None:
        async def work(txn) -> None:
            await txn.upsert(
                SUBJECT_EPOCHS, {"subject": subject}, {"subject": subject, "revokedAt": revoked_at}
            )

        await self._driver.transaction(work)

    async def close(self) -> None:
        await self._driver.close()


class PostgresRevocationStore(DriverRevocationStore):
    def __init__(
        self,
        pool: AsyncConnectionPool,
        *,
        table: str = "grantz_revocation_store",
    ) -> None:
        self.postgres_driver: PostgresStoreDriver = create_postgres_driver(
            pool, PostgresStoreDriverOptions(table=table)
        )
        super().__init__(self.postgres_driver)


def _parse_ms(value: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
