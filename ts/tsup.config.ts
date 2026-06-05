import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'packages/core/src/index.ts',
    'signer-local': 'packages/signer-local/src/index.ts',
    'revocation-convex': 'packages/revocation-convex/src/index.ts',
    'revocation-local': 'packages/revocation-local/src/index.ts',
    'revocation-postgres': 'packages/revocation-postgres/src/index.ts',
  },
  format: 'esm',
  dts: true,
  splitting: true,
  clean: true,
  outDir: 'dist',
  target: 'es2022',
});
