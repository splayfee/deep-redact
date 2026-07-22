import { Censor, RedactionReason } from './types';

/**
 * The traversal's read-only view of a {@link Redactor}, shared by the full walk
 * and the path-plan walk. Key matching is split for speed: literal names in
 * {@link literalKeys} (O(1)), only true regex fragments in {@link keyRegex}.
 */
export interface WalkConfig {
  literalKeys: Set<string> | null;
  keyRegex: RegExp;
  hasKeyRegex: boolean;
  caseSensitive: boolean;
  valueRegex: RegExp | null;
  literalReplacement: string | null;
  censor: Censor | null;
  removeMatched: boolean;
  redactInstances: boolean;
  maxDepth: number;
  trackPath: boolean;
  mutate: boolean;
}

/**
 * Produces the value written in place of a match: the literal replacement
 * directly when there is one (no context built), else invokes the censor.
 */
export function censorValue(
  config: WalkConfig,
  original: unknown,
  key: string | null,
  reason: RedactionReason,
  path: readonly (string | number)[]
): unknown {
  if (config.literalReplacement !== null) {
    return config.literalReplacement;
  }
  return config.censor!(original, { key, matchedBy: reason, path: path.slice() });
}

/**
 * Whether `key` matches by name: a literal-set hit first (fast), then the regex
 * of non-literal fragments only when one exists.
 */
export function matchesKey(key: string, config: WalkConfig): boolean {
  const probe = config.caseSensitive ? key : key.toLowerCase();
  if (config.literalKeys?.has(probe) === true) {
    return true;
  }
  return config.hasKeyRegex && config.keyRegex.test(key);
}

/**
 * Censors every substring of `value` matching the value patterns, leaving the
 * rest intact. Returns the input unchanged when nothing matches.
 */
export function redactString(
  value: string,
  config: WalkConfig,
  path: readonly (string | number)[]
): string {
  const regex = config.valueRegex;
  if (regex === null) {
    return value;
  }
  const literal = config.literalReplacement;
  if (literal !== null) {
    return value.replace(regex, () => {
      return literal;
    });
  }
  return value.replace(regex, (match) => {
    return String(censorValue(config, match, null, RedactionReason.Value, path));
  });
}

export function isMap(value: object): boolean {
  return value instanceof Map;
}

export function isSet(value: object): boolean {
  return value instanceof Set;
}

export function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

/**
 * Whether a non-plain object should be descended into under `redactInstances`.
 * Excludes types whose internals a shallow key-walk would mangle.
 */
export function isRedactableInstance(value: object): boolean {
  if (value instanceof Date || value instanceof RegExp || value instanceof Promise) {
    return false;
  }
  if (value instanceof WeakMap || value instanceof WeakSet) {
    return false;
  }
  return !ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer);
}
