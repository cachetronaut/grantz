from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NotRequired, Protocol, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class Scope(TypedDict):
    action: str
    resource: str
    qualifier: NotRequired[str | dict[str, Any]]


class Grant(TypedDict, total=False):
    issuer: str
    subject: str
    audience: str
    actAs: str
    scopes: list[Scope]
    constraints: dict[str, int | float | bool | str | list[str]]
    binding: dict[str, str]
    notBefore: str
    expiresAt: str


class TokenClaims(Grant):
    id: str
    depth: int
    issuedAt: str
    parentId: NotRequired[str]


@dataclass(frozen=True)
class LocalKeyPair:
    key_id: str
    public_key_pem: str
    private_key_pem: str


class AttenuationError(Exception):
    pass


class RevocationStore(Protocol):
    async def is_revoked(
        self, jti: str, subject: str | None = None, issued_at: str | None = None
    ) -> bool: ...

    async def revoke(self, jti: str) -> None: ...


class InMemoryRevocationStore:
    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.subject_epochs: dict[str, str] = {}

    async def is_revoked(
        self, jti: str, subject: str | None = None, issued_at: str | None = None
    ) -> bool:
        if jti in self.revoked:
            return True
        if subject is None or issued_at is None:
            return False
        epoch = self.subject_epochs.get(subject)
        return epoch is not None and _parse(issued_at) <= _parse(epoch)

    async def revoke(self, jti: str) -> None:
        self.revoked.add(jti)

    async def revoke_subject(self, subject: str, revoked_at: str) -> None:
        self.subject_epochs[subject] = revoked_at


_next_jti = 1


def covers(granted: Scope, requested: Scope) -> bool:
    if granted["action"] not in {"*", requested["action"]}:
        return False
    resource = granted["resource"]
    requested_resource = requested["resource"]
    if (
        resource != "*"
        and resource != requested_resource
        and not (resource.endswith(".*") and requested_resource.startswith(resource[:-1]))
    ):
        return False
    granted_qualifier = granted.get("qualifier")
    if granted_qualifier is None:
        return True
    return _canonical(granted_qualifier) == _canonical(requested.get("qualifier"))


async def mint(
    grant: Grant, key_pair: LocalKeyPair, *, now: str | None = None, jti: str | None = None
) -> str:
    claims: TokenClaims = {
        **grant,
        "id": jti or _next_id(),
        "depth": 0,
        "issuedAt": now or _now(),
    }  # type: ignore[typeddict-item]
    return _sign(_canonical(claims), key_pair)


async def verify(
    token: str,
    key_pair: LocalKeyPair,
    *,
    now: str | None = None,
    audience: str | None = None,
    revocation: RevocationStore | None = None,
) -> tuple[bool, TokenClaims | str]:
    try:
        payload = _verify_signature(token, key_pair)
        claims = json.loads(payload)
    except (InvalidSignature, ValueError, json.JSONDecodeError) as error:
        return False, f"bad_sig:{error}"
    now_dt = _parse(now or _now())
    if "notBefore" in claims and now_dt < _parse(claims["notBefore"]):
        return False, "not_yet"
    if now_dt >= _parse(claims["expiresAt"]):
        return False, "expired"
    if audience is not None and claims.get("audience") != audience:
        return False, "wrong_audience"
    if revocation is not None and await revocation.is_revoked(
        claims["id"], claims["subject"], claims["issuedAt"]
    ):
        return False, "revoked"
    return True, claims


async def attenuate(
    parent_token: str,
    narrowing: Grant,
    key_pair: LocalKeyPair,
    *,
    now: str | None = None,
    jti: str | None = None,
) -> str:
    ok, value = await verify(parent_token, key_pair, now=now)
    if not ok or not isinstance(value, dict):
        raise AttenuationError(str(value))
    parent: TokenClaims = value  # type: ignore[assignment]
    child_scopes = narrowing.get("scopes", parent["scopes"])
    if not all(
        any(covers(parent_scope, child_scope) for parent_scope in parent["scopes"])
        for child_scope in child_scopes
    ):
        raise AttenuationError("Child scopes must be covered by parent scopes")
    expires_at = narrowing.get("expiresAt", parent["expiresAt"])
    if _parse(expires_at) > _parse(parent["expiresAt"]):
        raise AttenuationError("Child expiry cannot exceed parent expiry")
    claims: TokenClaims = {
        "issuer": parent["issuer"],
        "subject": narrowing.get("subject", parent["subject"]),
        "audience": narrowing.get("audience", parent.get("audience", "")),
        "scopes": child_scopes,
        "constraints": {**parent.get("constraints", {}), **narrowing.get("constraints", {})},
        "binding": {**parent.get("binding", {}), **narrowing.get("binding", {})},
        "expiresAt": expires_at,
        "id": jti or _next_id(),
        "parentId": parent["id"],
        "depth": parent["depth"] + 1,
        "issuedAt": now or _now(),
    }  # type: ignore[typeddict-item]
    return _sign(_canonical(claims), key_pair)


def authorize(
    claims: TokenClaims, scope: Scope, context: dict[str, str] | None = None
) -> tuple[bool, str]:
    if not any(covers(granted, scope) for granted in claims["scopes"]):
        return False, "scope"
    binding = claims.get("binding", {})
    context = context or {}
    for key, value in binding.items():
        if context.get(key) != value:
            return False, "binding"
    return True, "ok"


def generate_local_key_pair(key_id: str = "local-ed25519") -> LocalKeyPair:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return LocalKeyPair(
        key_id=key_id,
        public_key_pem=public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
        private_key_pem=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    )


def _sign(payload: str, key_pair: LocalKeyPair) -> str:
    private_key = serialization.load_pem_private_key(
        key_pair.private_key_pem.encode(), password=None
    )
    assert isinstance(private_key, Ed25519PrivateKey)
    header = _b64(
        json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": key_pair.key_id}, separators=(",", ":"))
    )
    body = _b64(payload)
    signing_input = f"{header}.{body}"
    signature = private_key.sign(signing_input.encode())
    return f"{signing_input}.{_b64(signature)}"


def _verify_signature(token: str, key_pair: LocalKeyPair) -> str:
    header, payload, signature = token.split(".")
    header_value = json.loads(_unb64(header).decode())
    if header_value.get("alg") != "EdDSA" or header_value.get("kid") != key_pair.key_id:
        raise ValueError("unsupported header")
    public_key = serialization.load_pem_public_key(key_pair.public_key_pem.encode())
    assert isinstance(public_key, Ed25519PublicKey)
    public_key.verify(_unb64(signature), f"{header}.{payload}".encode())
    return _unb64(payload).decode()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _b64(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _next_id() -> str:
    global _next_jti
    value = f"jti_{_next_jti}"
    _next_jti += 1
    return value
