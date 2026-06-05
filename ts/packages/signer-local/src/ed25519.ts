import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
  verify,
} from 'node:crypto';
import type { Signer, Verifier } from '@grantz/core';

const HEADER = { alg: 'EdDSA', typ: 'JWT' };

export interface LocalKeyPair {
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export function generateLocalKeyPair(keyId = 'local-ed25519'): LocalKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    keyId,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

export class Ed25519LocalSigner implements Signer {
  readonly keyId: string;
  private readonly privateKey: KeyObject;

  constructor(keyPair: LocalKeyPair) {
    this.keyId = keyPair.keyId;
    this.privateKey = createPrivateKey(keyPair.privateKeyPem);
  }

  async sign(payload: string): Promise<string> {
    const encodedHeader = base64url(JSON.stringify({ ...HEADER, kid: this.keyId }));
    const encodedPayload = base64url(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = sign(null, Buffer.from(signingInput), this.privateKey);
    return `${signingInput}.${base64url(signature)}`;
  }
}

export class Ed25519LocalVerifier implements Verifier {
  private readonly keys = new Map<string, KeyObject>();

  constructor(keyPairs: readonly Pick<LocalKeyPair, 'keyId' | 'publicKeyPem'>[]) {
    for (const keyPair of keyPairs) {
      this.keys.set(keyPair.keyId, createPublicKey(keyPair.publicKeyPem));
    }
  }

  async verify(token: string): Promise<{ payload: string; keyId: string }> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Malformed compact token');
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    if (
      encodedHeader === undefined ||
      encodedPayload === undefined ||
      encodedSignature === undefined
    ) {
      throw new Error('Malformed compact token');
    }
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8')) as {
      alg?: string;
      kid?: string;
    };
    if (header.alg !== 'EdDSA' || header.kid === undefined) {
      throw new Error('Unsupported token header');
    }
    const publicKey = this.keys.get(header.kid);
    if (publicKey === undefined) {
      throw new Error('Unknown key id');
    }
    const ok = verify(
      null,
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      publicKey,
      Buffer.from(encodedSignature, 'base64url'),
    );
    if (!ok) {
      throw new Error('Bad signature');
    }
    return {
      payload: Buffer.from(encodedPayload, 'base64url').toString('utf8'),
      keyId: header.kid,
    };
  }
}

function base64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}
