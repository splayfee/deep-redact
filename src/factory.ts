import { Redactor } from './Redactor';
import { RedactorOptions } from './types';

/**
 * Creates a {@link Redactor}. Sugar for `new Redactor(options)` that reads
 * nicely at call sites and keeps construction consistent across the codebase.
 */
export function createRedactor(options?: RedactorOptions): Redactor {
  return new Redactor(options);
}

/**
 * A shared redactor configured with the default patterns, used by {@link redact}.
 */
const defaultRedactor = new Redactor();

/**
 * Returns a censored deep copy of `value` using the default pattern set. For a
 * customized match list, build your own instance with {@link createRedactor}.
 */
export function redact(value: unknown): unknown {
  return defaultRedactor.redact(value);
}
