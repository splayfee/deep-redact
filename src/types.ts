/**
 * Why a value was redacted, passed to a {@link Censor} so it can react to the
 * cause (a matched key, path, or substring in a value).
 */
export enum RedactionReason {
  Key = 'key',
  Path = 'path',
  Value = 'value'
}

/**
 * Context handed to a {@link Censor} describing what is being redacted.
 */
export interface RedactionContext {
  /** The matched key, or `null` for an array element or a value-pattern match. */
  key: string | null;

  /** Path from the root to the value; empty unless path tracking is active. */
  path: readonly (string | number)[];

  /** What triggered the redaction. */
  matchedBy: RedactionReason;
}

/**
 * Produces the value written in place of a match. Return a string marker, or
 * anything else to reshape the output (e.g. a partial mask).
 */
export type Censor = (value: unknown, context: RedactionContext) => unknown;

/**
 * The minimal contract a redactor exposes: turn a value into a censored copy.
 * Depending on this rather than the concrete {@link Redactor} lets callers
 * accept any conforming engine.
 */
export interface RedactionEngine {
  redact(value: unknown): unknown;
}

/**
 * Construction options for a {@link Redactor}. Every field is optional; the
 * defaults match the standalone {@link redact} helper.
 */
export interface RedactorOptions {
  /**
   * Key-name regex fragments (e.g. `api[-_]?key`). Defaults to
   * {@link DEFAULT_SENSITIVE_KEY_PATTERNS}; pass `[]` to start empty.
   */
  patterns?: readonly string[];

  /**
   * Patterns matched against string *values*; matching substrings are censored
   * in place (JWTs, cards, emails). Strings or `RegExp`s; supplied flags are
   * ignored (global + `caseSensitive`).
   */
  valuePatterns?: readonly (string | RegExp)[];

  /**
   * Exact paths to redact (`headers.cookie`, `*.password`, `items[*].token`).
   * When set, runs in fast **path-only mode**: `patterns`/`valuePatterns` are
   * not applied. Leave empty for the full walk.
   */
  paths?: readonly string[];

  /**
   * Value written in place of a match: a verbatim string, or a {@link Censor}
   * function for partial masks like `****1234`. Defaults to `[redacted]`;
   * ignored when {@link removeMatched} is `true`.
   */
  replacement?: string | Censor;

  /**
   * When `true`, drop the matched key entirely instead of replacing its value.
   * Only affects keyed containers (objects and `Map`s). Defaults to `false`.
   */
  removeMatched?: boolean;

  /**
   * When `true`, redact **in place** and return the same object (fastest, but
   * destroys the input). Applies only in registered-`paths` mode. Defaults to
   * `false`.
   */
  mutate?: boolean;

  /**
   * When `true`, compile paths to a `new Function` redactor (fastest). Needs
   * `mutate`, wildcard-free `paths`, a string `replacement` (or `removeMatched`);
   * self-disables under strict CSP. Defaults to `false`.
   */
  compile?: boolean;

  /**
   * When `true`, descend into `Error`s (incl. `message`/`stack`) and class
   * instances, copying to censored plain objects. `Date`/`RegExp`/typed arrays
   * still pass through. Defaults to `false`.
   */
  redactInstances?: boolean;

  /**
   * Max depth to descend before emitting a truncation marker. Non-negative
   * integer. Defaults to `8`.
   */
  maxDepth?: number;

  /**
   * When `true`, key and value matching is case-sensitive. Defaults to `false`.
   */
  caseSensitive?: boolean;

  /**
   * When `true` (default), a pattern must match the whole key (`token` matches
   * `token` but not `tokenCount`). Set `false` for substring matching.
   */
  matchWholeKey?: boolean;
}
