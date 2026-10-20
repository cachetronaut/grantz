import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@grantz/core': fileURLToPath(new URL('packages/core/src/index.ts', import.meta.url)),
      '@grantz/signer-local': fileURLToPath(
        new URL('packages/signer-local/src/index.ts', import.meta.url),
      ),
      '@grantz/revocation-convex': fileURLToPath(
        new URL('packages/revocation-convex/src/index.ts', import.meta.url),
      ),
      '@grantz/revocation-local': fileURLToPath(
        new URL('packages/revocation-local/src/index.ts', import.meta.url),
      ),
      '@grantz/revocation-postgres': fileURLToPath(
        new URL('packages/revocation-postgres/src/index.ts', import.meta.url),
      ),
    },
  },
});
