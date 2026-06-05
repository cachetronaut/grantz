import { AttenuationError } from './errors.js';
import type { ConstraintValue } from './types.js';

export function composeConstraints(
  parent: Readonly<Record<string, ConstraintValue>> = {},
  child: Readonly<Record<string, ConstraintValue>> = {},
): Readonly<Record<string, ConstraintValue>> {
  const out: Record<string, ConstraintValue> = { ...parent };
  for (const [key, childValue] of Object.entries(child)) {
    const parentValue = parent[key];
    out[key] = composeConstraint(key, parentValue, childValue);
  }
  return out;
}

function composeConstraint(
  key: string,
  parent: ConstraintValue | undefined,
  child: ConstraintValue,
): ConstraintValue {
  if (parent === undefined) {
    return child;
  }
  if (typeof parent === 'number' && typeof child === 'number') {
    return Math.min(parent, child);
  }
  if (typeof parent === 'boolean' && typeof child === 'boolean') {
    if (parent === false && child === true) {
      throw new AttenuationError(`Constraint ${key} would relax a boolean denial`);
    }
    return parent && child;
  }
  if (Array.isArray(parent) && Array.isArray(child)) {
    return [...new Set([...parent, ...child])].sort();
  }
  if (typeof parent === 'string' && typeof child === 'string') {
    if (parent !== child) {
      throw new AttenuationError(`Constraint ${key} cannot change string value`);
    }
    return parent;
  }
  throw new AttenuationError(`Constraint ${key} has incompatible shape`);
}
