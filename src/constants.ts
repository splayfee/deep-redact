/**
 * Default replacement written in place of a sensitive value.
 */
export const DEFAULT_REDACTED = '[redacted]';

/**
 * Written in place of a value that references one of its own ancestors, so a
 * cyclic structure never causes infinite recursion.
 */
export const CIRCULAR_MARKER = '[circular]';

/**
 * Written in place of a value nested deeper than `maxDepth`. Acts as a safety
 * net against pathological structures.
 */
export const TRUNCATED_MARKER = '[truncated]';

/**
 * How deep the walk descends before it stops and emits {@link TRUNCATED_MARKER}.
 */
export const DEFAULT_MAX_DEPTH = 8;

/**
 * Default secret-bearing key names as regex fragments. `[-_]?` allows an
 * optional separator, so `apiKey`, `api_key`, and `API-KEY` all match one
 * `api[-_]?key` fragment.
 */
export const DEFAULT_SENSITIVE_KEY_PATTERNS: readonly string[] = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'access[-_]?token',
  'refresh[-_]?token',
  'api[-_]?key',
  'access[-_]?key[-_]?id',
  'secret[-_]?access[-_]?key',
  'authorization',
  'auth[-_]?token',
  'cookie',
  'set[-_]?cookie',
  'session[-_]?id',
  'credentials?',
  'private[-_]?key'
];
