import { GrantError } from './errors.js';
import type { ClockOptions, TokenClaims, VerifyFailureCode } from './types.js';

const ISO_INSTANT =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

export function parseInstant(value: string): number {
  const match = typeof value === 'string' ? ISO_INSTANT.exec(value) : null;
  if (match === null) {
    throw new GrantError('invalid_date', 'Expected an ISO timestamp with a timezone');
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const zone = match[8] ?? '';
  const instant = Date.parse(value);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (days[month - 1] ?? 0) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59)) ||
    !Number.isFinite(instant)
  ) {
    throw new GrantError('invalid_date', 'Invalid ISO timestamp');
  }
  return instant;
}

export function clockInstant(options: ClockOptions): number {
  if (typeof options.now === 'string') {
    return parseInstant(options.now);
  }
  const instant = (options.now?.() ?? new Date()).getTime();
  if (!Number.isFinite(instant)) {
    throw new GrantError('invalid_date', 'Clock returned an invalid date');
  }
  return instant;
}

export function validateDates(claims: TokenClaims): void {
  parseInstant(claims.issuedAt);
  parseInstant(claims.expiresAt);
  if (claims.notBefore !== undefined) {
    parseInstant(claims.notBefore);
  }
}

export function validityFailure(
  claims: TokenClaims,
  options: ClockOptions,
): VerifyFailureCode | undefined {
  try {
    validateDates(claims);
    const now = clockInstant(options);
    if (claims.notBefore !== undefined && now < parseInstant(claims.notBefore)) {
      return 'not_yet';
    }
    if (now >= parseInstant(claims.expiresAt)) {
      return 'expired';
    }
    return undefined;
  } catch (error) {
    if (error instanceof GrantError) {
      return 'invalid_date';
    }
    throw error;
  }
}
