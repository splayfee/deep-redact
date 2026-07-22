import { Redactor } from './Redactor';
import { RedactionEngine, RedactorOptions } from './types';

/**
 * Console methods routed through redaction by default. Single source of truth;
 * {@link ConsoleMethodName} is derived from it.
 */
const DEFAULT_CONSOLE_METHODS = [
  'log',
  'info',
  'warn',
  'error',
  'debug',
  'trace',
  'dir',
  'dirxml',
  'group',
  'groupCollapsed',
  'table',
  'assert'
] as const;

/**
 * A console method name eligible for patching.
 */
export type ConsoleMethodName = (typeof DEFAULT_CONSOLE_METHODS)[number];

/**
 * Where and what to patch, independent of how the redactor is obtained.
 */
interface ConsolePatchOptions {
  /**
   * The console to patch. Defaults to the global `console`.
   */
  target?: Console;

  /**
   * Which console methods to patch. Defaults to every data-bearing method.
   */
  methods?: readonly ConsoleMethodName[];
}

/**
 * Options for {@link enableConsoleRedaction}. Supply either a pre-built
 * `redactor` or {@link RedactorOptions} to build one - never both.
 */
export type ConsoleRedactionOptions =
  | (ConsolePatchOptions & { redactor: RedactionEngine })
  | (ConsolePatchOptions & RedactorOptions & { redactor?: undefined });

/**
 * Restores the console patched by the most recent {@link enableConsoleRedaction}
 * call, or `null` when redaction is not currently enabled.
 */
let activeRestore: (() => void) | null = null;

/**
 * Runs every argument through the redactor. Redaction failures fall back to the
 * original argument so patched console methods can never throw or swallow output.
 */
function redactArgs(redactor: RedactionEngine, args: unknown[]): unknown[] {
  return args.map(function (arg): unknown {
    try {
      return redactor.redact(arg);
    } catch {
      return arg;
    }
  });
}

/**
 * Whether console redaction is currently active.
 */
export function isConsoleRedactionEnabled(): boolean {
  return activeRestore !== null;
}

/**
 * Restores the original console methods. Safe to call when redaction is not
 * enabled (it does nothing).
 */
export function disableConsoleRedaction(): void {
  if (activeRestore) {
    activeRestore();
    activeRestore = null;
  }
}

/**
 * Rewires `console.*` so every argument is redacted before printing. Calling it
 * again replaces any previous patch; returns a restore function (same as
 * {@link disableConsoleRedaction}).
 */
export function enableConsoleRedaction(options: ConsoleRedactionOptions = {}): () => void {
  // Re-applying cleanly replaces any prior patch.
  disableConsoleRedaction();

  const target = options.target ?? globalThis.console;
  const redactor = options.redactor ?? new Redactor(options);
  const methods = options.methods ?? DEFAULT_CONSOLE_METHODS;

  const source = target as unknown as Record<string, unknown>;
  const originals = new Map<ConsoleMethodName, (...args: unknown[]) => unknown>();
  for (const method of methods) {
    const current = source[method];
    if (typeof current !== 'function') {
      continue;
    }
    const original = current as (...args: unknown[]) => unknown;
    originals.set(method, original);
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
      return original.apply(target, redactArgs(redactor, args));
    };
    source[method] = wrapped;
  }

  activeRestore = function (): void {
    for (const [method, original] of originals) {
      source[method] = original;
    }
  };
  return activeRestore;
}
