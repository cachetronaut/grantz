from __future__ import annotations

from datetime import datetime

from dockbay import (
    ConvexOperationContext,
    ConvexOperationDriver,
    ConvexStoreOperation,
    JsonValue,
)

REVOKE_JTI = "revocation.revokeJti"
REVOKE_SUBJECT = "revocation.revokeSubject"
IS_REVOKED = "revocation.isRevoked"


class ConvexRevocationStore:
    def __init__(
        self,
        driver: ConvexOperationDriver,
        *,
        operations: dict[str, str] | None = None,
    ) -> None:
        self._driver = driver
        self._operations = {
            "revoke_jti": REVOKE_JTI,
            "revoke_subject": REVOKE_SUBJECT,
            "is_revoked": IS_REVOKED,
            **(operations or {}),
        }

    async def is_revoked(
        self, jti: str, subject: str | None = None, issued_at: str | None = None
    ) -> bool:
        result = await self._driver.call(
            self._operations["is_revoked"],
            {"jti": jti, "subject": subject, "issuedAt": issued_at},
        )
        assert isinstance(result, dict)
        return result["revoked"] is True

    async def revoke(self, jti: str) -> None:
        await self._driver.call(self._operations["revoke_jti"], {"jti": jti})

    async def revoke_subject(self, subject: str, revoked_at: str) -> None:
        await self._driver.call(
            self._operations["revoke_subject"], {"subject": subject, "revokedAt": revoked_at}
        )

    async def close(self) -> None:
        return None


def create_revocation_operations() -> list[ConvexStoreOperation]:
    revoked_jtis: set[str] = set()
    subject_epochs: dict[str, str] = {}

    async def revoke_jti(_ctx: ConvexOperationContext, input_value: JsonValue) -> JsonValue:
        assert isinstance(input_value, dict)
        revoked_jtis.add(str(input_value["jti"]))
        return None

    async def revoke_subject(_ctx: ConvexOperationContext, input_value: JsonValue) -> JsonValue:
        assert isinstance(input_value, dict)
        subject_epochs[str(input_value["subject"])] = str(input_value["revokedAt"])
        return None

    async def is_revoked(_ctx: ConvexOperationContext, input_value: JsonValue) -> JsonValue:
        assert isinstance(input_value, dict)
        jti = str(input_value["jti"])
        if jti in revoked_jtis:
            return {"revoked": True}
        subject = input_value.get("subject")
        issued_at = input_value.get("issuedAt")
        if not isinstance(subject, str) or not isinstance(issued_at, str):
            return {"revoked": False}
        epoch = subject_epochs.get(subject)
        return {"revoked": epoch is not None and _parse_ms(issued_at) <= _parse_ms(epoch)}

    return [
        ConvexStoreOperation(name=REVOKE_JTI, kind="mutation", run=revoke_jti),
        ConvexStoreOperation(name=REVOKE_SUBJECT, kind="mutation", run=revoke_subject),
        ConvexStoreOperation(name=IS_REVOKED, kind="query", run=is_revoked),
    ]


def _parse_ms(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
