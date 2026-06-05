import { mint, verify } from '@grantz/core';
import { InMemoryRevocationStore } from '@grantz/revocation-local';
import { describe, expect, it } from 'vitest';
import { Ed25519LocalSigner, Ed25519LocalVerifier, generateLocalKeyPair } from '../src/index';

const NOW = '2026-06-04T12:00:00.000Z';
const LATER = '2026-06-04T12:05:00.000Z';

describe('Ed25519LocalSigner', () => {
  it('mints and verifies a compact signed token', async () => {
    const keyPair = generateLocalKeyPair('test-key');
    const signer = new Ed25519LocalSigner(keyPair);
    const verifier = new Ed25519LocalVerifier([keyPair]);

    const token = await mint(
      {
        issuer: 'issuer_gateway',
        subject: 'principal_agent_01',
        audience: 'gateway',
        scopes: [{ action: 'tool.call', resource: 'mcp://browser.open' }],
        expiresAt: '2026-06-04T13:00:00.000Z',
      },
      signer,
      { now: NOW, id: 'jti_signed' },
    );

    expect(token.split('.')).toHaveLength(3);
    const verified = await verify(token, verifier, { now: LATER, audience: 'gateway' });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.keyId).toBe('test-key');
      expect(verified.claims.id).toBe('jti_signed');
    }
  });

  it('rejects a tampered signature', async () => {
    const keyPair = generateLocalKeyPair('test-key');
    const signer = new Ed25519LocalSigner(keyPair);
    const verifier = new Ed25519LocalVerifier([keyPair]);
    const token = await mint(
      {
        issuer: 'issuer_gateway',
        subject: 'principal_agent_01',
        scopes: [{ action: 'tool.call', resource: 'mcp://browser.open' }],
        expiresAt: '2026-06-04T13:00:00.000Z',
      },
      signer,
      { now: NOW, id: 'jti_signed' },
    );

    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.x${parts[2]}`;
    await expect(verify(tampered, verifier, { now: LATER })).resolves.toMatchObject({
      ok: false,
      code: 'bad_sig',
    });
  });

  it('honors expiry, audience, and revocation checks', async () => {
    const keyPair = generateLocalKeyPair('test-key');
    const signer = new Ed25519LocalSigner(keyPair);
    const verifier = new Ed25519LocalVerifier([keyPair]);
    const revocation = new InMemoryRevocationStore();
    const token = await mint(
      {
        issuer: 'issuer_gateway',
        subject: 'principal_agent_01',
        audience: 'gateway',
        scopes: [{ action: 'tool.call', resource: 'mcp://browser.open' }],
        expiresAt: '2026-06-04T13:00:00.000Z',
      },
      signer,
      { now: NOW, id: 'jti_signed' },
    );

    await expect(verify(token, verifier, { now: LATER, audience: 'other' })).resolves.toMatchObject(
      {
        ok: false,
        code: 'wrong_audience',
      },
    );
    await expect(
      verify(token, verifier, { now: '2026-06-04T13:00:00.000Z' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'expired',
    });
    await revocation.revoke('jti_signed');
    await expect(verify(token, verifier, { now: LATER, revocation })).resolves.toMatchObject({
      ok: false,
      code: 'revoked',
    });
  });
});
