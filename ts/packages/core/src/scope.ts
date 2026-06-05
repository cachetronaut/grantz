import { canonicalize } from './canonical.js';
import type { Scope } from './types.js';

export function covers(granted: Scope, requested: Scope): boolean {
  return (
    actionCovers(granted.action, requested.action) &&
    resourceCovers(granted.resource, requested.resource) &&
    qualifierCovers(granted.qualifier, requested.qualifier)
  );
}

function actionCovers(granted: string, requested: string): boolean {
  return granted === '*' || granted === requested;
}

function resourceCovers(granted: string, requested: string): boolean {
  if (granted === '*' || granted === requested) {
    return true;
  }
  if (granted.endsWith('.*')) {
    const prefix = granted.slice(0, -1);
    return requested.startsWith(prefix);
  }
  return false;
}

function qualifierCovers(granted: Scope['qualifier'], requested: Scope['qualifier']): boolean {
  if (granted === undefined) {
    return true;
  }
  if (requested === undefined) {
    return false;
  }
  return canonicalize(granted) === canonicalize(requested);
}
