/**
 * A regular expression that never matches, used when no regex patterns exist.
 */
export const NEVER_MATCH = /(?!)/;

/**
 * Characters that give a pattern regex meaning. A pattern with none of these is
 * a literal key name and can go in a fast `Set` instead of the alternation.
 */
const HAS_REGEX_META = /[.*+?^${}()|[\]\\]/;

/** The compiled forms of a key-pattern set. */
export interface KeyMatchers {
  /** Full alternation of every pattern - exposed via `Redactor.regex`. */
  full: RegExp;
  /** Literal whole-key names for O(1) lookup, or `null` when there are none. */
  literalKeys: Set<string> | null;
  /** Alternation of only the fragments that need regex. */
  keyRegex: RegExp;
  /** Whether {@link keyRegex} holds any real pattern. */
  hasKeyRegex: boolean;
}

/**
 * Throws {@link SyntaxError} if `pattern` is not a valid regular expression.
 */
export function assertCompilable(pattern: string): void {
  try {
    void new RegExp(pattern);
  } catch (error) {
    throw new SyntaxError(
      `auto-redact: pattern "${pattern}" is not a valid regular expression: ${(error as Error).message}`,
      { cause: error }
    );
  }
}

/**
 * Validates a key-pattern list (non-empty strings, each a valid regex) and
 * returns it as a plain array.
 */
export function normalizeKeyPatterns(patterns: readonly string[]): string[] {
  if (!Array.isArray(patterns)) {
    throw new TypeError('auto-redact: patterns must be an array of strings.');
  }
  const result: string[] = [];
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new TypeError(
        `auto-redact: each pattern must be a non-empty string (received ${JSON.stringify(pattern)}).`
      );
    }
    assertCompilable(pattern);
    result.push(pattern);
  }
  return result;
}

function compileAlternation(
  patterns: readonly string[],
  caseSensitive: boolean,
  matchWholeKey: boolean
): RegExp {
  if (patterns.length === 0) {
    return NEVER_MATCH;
  }
  const flags = caseSensitive ? '' : 'i';
  const body = patterns.join('|');
  return new RegExp(matchWholeKey ? `^(?:${body})$` : `(?:${body})`, flags);
}

/**
 * Splits patterns into a literal-name {@link Set} (O(1) lookup) and a regex of
 * only the fragments that need it. Literals are split out for whole-key matching.
 */
export function compileKeyMatchers(
  patterns: readonly string[],
  caseSensitive: boolean,
  matchWholeKey: boolean
): KeyMatchers {
  const literals = new Set<string>();
  const regexParts: string[] = [];
  for (const pattern of patterns) {
    if (matchWholeKey && !HAS_REGEX_META.test(pattern)) {
      literals.add(caseSensitive ? pattern : pattern.toLowerCase());
    } else {
      regexParts.push(pattern);
    }
  }
  return {
    full: compileAlternation(patterns, caseSensitive, matchWholeKey),
    literalKeys: literals.size > 0 ? literals : null,
    keyRegex:
      regexParts.length > 0
        ? compileAlternation(regexParts, caseSensitive, matchWholeKey)
        : NEVER_MATCH,
    hasKeyRegex: regexParts.length > 0
  };
}

/**
 * Validates and compiles value patterns into one global alternation, or `null`
 * when none are given. Flags on a supplied `RegExp` are ignored.
 */
export function compileValueRegex(
  patterns: readonly (string | RegExp)[],
  caseSensitive: boolean
): RegExp | null {
  if (!Array.isArray(patterns)) {
    throw new TypeError('auto-redact: valuePatterns must be an array of strings or RegExps.');
  }
  const sources: string[] = [];
  for (const pattern of patterns) {
    if (pattern instanceof RegExp) {
      sources.push(pattern.source);
      continue;
    }
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new TypeError(
        `auto-redact: each value pattern must be a non-empty string or RegExp (received ${JSON.stringify(pattern)}).`
      );
    }
    assertCompilable(pattern);
    sources.push(pattern);
  }
  if (sources.length === 0) {
    return null;
  }
  const flags = caseSensitive ? 'g' : 'gi';
  return new RegExp(
    sources
      .map((source) => {
        return `(?:${source})`;
      })
      .join('|'),
    flags
  );
}

/**
 * Validates a path list (non-empty strings) and returns it unchanged.
 */
export function validatePaths(paths: readonly string[]): readonly string[] {
  if (!Array.isArray(paths)) {
    throw new TypeError('auto-redact: paths must be an array of strings.');
  }
  for (const path of paths) {
    if (typeof path !== 'string' || path.length === 0) {
      throw new TypeError(
        `auto-redact: each path must be a non-empty string (received ${JSON.stringify(path)}).`
      );
    }
  }
  return paths;
}
