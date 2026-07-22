export { Redactor } from './Redactor';
export { createRedactor, redact } from './factory';
export {
  enableConsoleRedaction,
  disableConsoleRedaction,
  isConsoleRedactionEnabled
} from './consoleRedaction';
export { RedactionReason } from './types';
export type { Censor, RedactionContext, RedactionEngine, RedactorOptions } from './types';
export type { ConsoleMethodName, ConsoleRedactionOptions } from './consoleRedaction';
export {
  DEFAULT_REDACTED,
  DEFAULT_MAX_DEPTH,
  DEFAULT_SENSITIVE_KEY_PATTERNS,
  CIRCULAR_MARKER,
  TRUNCATED_MARKER
} from './constants';
