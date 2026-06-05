from __future__ import annotations

import pytest

from grantz import authorize, covers, generate_local_key_pair, mint, verify


def test_scope_coverage() -> None:
    assert covers(
        {"action": "*", "resource": "mcp://browser.*"},
        {"action": "tool.call", "resource": "mcp://browser.open"},
    )
    assert not covers(
        {"action": "read", "resource": "artifact.report"},
        {"action": "write", "resource": "artifact.report"},
    )


@pytest.mark.asyncio
async def test_mint_verify_authorize() -> None:
    key_pair = generate_local_key_pair("test-key")
    token = await mint(
        {
            "issuer": "issuer_gateway",
            "subject": "principal_agent_01",
            "audience": "gateway",
            "scopes": [{"action": "tool.call", "resource": "mcp://browser.open"}],
            "binding": {"runId": "run_demo"},
            "expiresAt": "2026-06-04T13:00:00.000Z",
        },
        key_pair,
        now="2026-06-04T12:00:00.000Z",
        jti="jti_demo",
    )

    ok, value = await verify(token, key_pair, now="2026-06-04T12:05:00.000Z", audience="gateway")

    assert ok
    assert isinstance(value, dict)
    assert authorize(
        value, {"action": "tool.call", "resource": "mcp://browser.open"}, {"runId": "run_demo"}
    ) == (True, "ok")
