import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Grant, Scope, Signer, Verifier } from '../src/index';
import {
  AttenuationError,
  attenuate,
  authorize,
  canonicalize,
  composeConstraints,
  covers,
  mint,
  verify,
} from '../src/index';

const NOW = '2026-06-04T12:00:00.000Z';
const LATER = '2026-06-04T12:05:00.000Z';
const EXPIRES = '2026-06-04T13:00:00.000Z';

const scopeFixturePath = join(import.meta.dirname, 'conformance', 'scope', 'basic', 'scope.json');
const sharedScopeFixturePath = join(
  import.meta.dirname,
  '..',
  '..',
  '..',
  '..',
  'fixtures',
  'conformance',
  'scope',
  'basic',
  'scope.json',
);

class JsonSigner implements Signer {
  readonly keyId = 'test-key';
  async sign(payload: string): Promise<string> {
    return payload;
  }
}

class JsonVerifier implements Verifier {
  async verify(token: string): Promise<{ payload: string; keyId: string }> {
    return { payload: token, keyId: 'test-key' };
  }
}

function rootGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    issuer: 'issuer_gateway',
    subject: 'principal_agent_01',
    audience: 'gateway',
    scopes: [{ action: '*', resource: 'mcp://browser.*' }],
    constraints: { max_spend_usd: 2, pii_export: false },
    binding: { runId: 'run_demo_01' },
    expiresAt: EXPIRES,
    ...overrides,
  };
}

describe('scope coverage', () => {
  it('vendors the shared scope fixture unchanged', () => {
    expect(readFileSync(scopeFixturePath, 'utf8')).toBe(
      readFileSync(sharedScopeFixturePath, 'utf8'),
    );
  });

  it('covers wildcard actions and hierarchical resources', () => {
    expect(
      covers(
        { action: '*', resource: 'artifact.*' },
        { action: 'read', resource: 'artifact.report' },
      ),
    ).toBe(true);
    expect(
      covers(
        { action: 'read', resource: 'artifact.report' },
        { action: 'write', resource: 'artifact.report' },
      ),
    ).toBe(false);
  });

  it('treats an omitted qualifier as broader', () => {
    const request = JSON.parse(readFileSync(scopeFixturePath, 'utf8')) as Scope;
    expect(covers({ action: 'tool.call', resource: 'mcp://browser.open' }, request)).toBe(true);
    expect(canonicalize(request)).toBe(
      '{"action":"tool.call","qualifier":{"origin":"local-demo"},"resource":"mcp://browser.open"}',
    );
  });
});

describe('attenuation', () => {
  it('mints and verifies a root grant', async () => {
    const token = await mint(rootGrant(), new JsonSigner(), { now: NOW, id: 'jti_root' });
    const verified = await verify(token, new JsonVerifier(), { now: LATER, audience: 'gateway' });

    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.claims.depth).toBe(0);
      expect(verified.claims.id).toBe('jti_root');
    }
  });

  it('allows narrower child scopes and tighter numeric constraints', async () => {
    const signer = new JsonSigner();
    const verifier = new JsonVerifier();
    const parent = await mint(rootGrant(), signer, { now: NOW, id: 'jti_root' });
    const child = await attenuate(
      parent,
      {
        scopes: [{ action: 'tool.call', resource: 'mcp://browser.open' }],
        constraints: { max_spend_usd: 1 },
        expiresAt: '2026-06-04T12:30:00.000Z',
      },
      signer,
      verifier,
      { now: LATER, id: 'jti_child' },
    );
    const verified = await verify(child, verifier, { now: LATER });

    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.claims.depth).toBe(1);
      expect(verified.claims.parentId).toBe('jti_root');
      expect(verified.claims.constraints?.max_spend_usd).toBe(1);
    }
  });

  it('rejects child scopes that widen authority', async () => {
    const signer = new JsonSigner();
    const verifier = new JsonVerifier();
    const parent = await mint(rootGrant(), signer, { now: NOW, id: 'jti_root' });

    await expect(
      attenuate(
        parent,
        { scopes: [{ action: 'tool.call', resource: 'filesystem.*' }] },
        signer,
        verifier,
        { now: LATER },
      ),
    ).rejects.toBeInstanceOf(AttenuationError);
  });

  it('rejects child expiry that outlives the parent', async () => {
    const signer = new JsonSigner();
    const verifier = new JsonVerifier();
    const parent = await mint(rootGrant(), signer, { now: NOW, id: 'jti_root' });

    await expect(
      attenuate(parent, { expiresAt: '2026-06-04T14:00:00.000Z' }, signer, verifier, {
        now: LATER,
      }),
    ).rejects.toBeInstanceOf(AttenuationError);
  });
});

describe('authorization', () => {
  it('authorizes a covered scope with matching binding and returns constraints', async () => {
    const token = await mint(rootGrant(), new JsonSigner(), { now: NOW, id: 'jti_root' });
    const verified = await verify(token, new JsonVerifier(), { now: LATER });
    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }

    expect(
      authorize(verified.claims, {
        scope: { action: 'tool.call', resource: 'mcp://browser.open' },
        context: { runId: 'run_demo_01' },
      }),
    ).toEqual({ ok: true, constraints: { max_spend_usd: 2, pii_export: false } });
  });

  it('rejects a covered scope with the wrong binding', async () => {
    const token = await mint(rootGrant(), new JsonSigner(), { now: NOW, id: 'jti_root' });
    const verified = await verify(token, new JsonVerifier(), { now: LATER });
    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }

    expect(
      authorize(verified.claims, {
        scope: { action: 'tool.call', resource: 'mcp://browser.open' },
        context: { runId: 'run_other' },
      }),
    ).toEqual({ ok: false, reason: 'binding' });
  });
});

describe('constraint composition', () => {
  it('tightens known constraint shapes', () => {
    expect(
      composeConstraints(
        { max_spend_usd: 5, pii_export: false, human_approval_required_for: ['network'] },
        { max_spend_usd: 2, pii_export: false, human_approval_required_for: ['filesystem'] },
      ),
    ).toEqual({
      max_spend_usd: 2,
      pii_export: false,
      human_approval_required_for: ['filesystem', 'network'],
    });
  });
});
