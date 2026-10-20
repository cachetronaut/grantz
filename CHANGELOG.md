---
status: active
updated: 2026-10-20
description: Release history for the grant libraries.
keywords: [grantz, changelog, durable-state, typescript, bun]
---

# Changelog

## Unreleased

- Add pluggable TypeScript grant state through npm dockbay transactions and drivers, with an in-memory default.
- Add atomic single-use consumption and durable per-grant revocation with typed errors.
- Make TypeScript authorization asynchronous, require the presenting principal to match the subject, and recheck state and validity.
- Generate random UUID grant ids and reject duplicate explicit ids.
- Validate timezone-qualified ISO instants against an injectable clock; reject malformed dates and validity widening during attenuation.
- Prevent attenuation of single-use parents.
- Use published dockbay exports for revocation adapters and add built-package smoke checks for Node 24 and Bun 1.4.
- Consolidated TypeScript and Python implementations into one primitive repository.
