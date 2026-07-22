import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import {
  disableConsoleRedaction,
  enableConsoleRedaction,
  isConsoleRedactionEnabled
} from '../src/consoleRedaction';
import { Redactor } from '../src/Redactor';
import { DEFAULT_REDACTED } from '../src/constants';

/**
 * Builds a fake console whose methods are spies, so tests can assert on the
 * arguments the patched wrapper forwards to the real implementation.
 */
function makeFakeConsole(): Console {
  return {
    log: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    dir: vi.fn(),
    dirxml: vi.fn(),
    group: vi.fn(),
    groupCollapsed: vi.fn(),
    table: vi.fn(),
    assert: vi.fn()
  } as unknown as Console;
}

/**
 * Reads the underlying spy for a console method. Captured before patching (or
 * via the retained reference), it records what the wrapper forwards.
 */
function spyFor(fn: unknown): Mock {
  return fn as Mock;
}

afterEach((): void => {
  disableConsoleRedaction();
});

describe('enableConsoleRedaction', () => {
  it('redacts object arguments before forwarding to the console', (): void => {
    const target = makeFakeConsole();
    const logSpy = spyFor(target.log);
    enableConsoleRedaction({ target });
    target.log('message', { user: 'ada', password: 'hunter2' });
    expect(logSpy).toHaveBeenCalledWith('message', { user: 'ada', password: DEFAULT_REDACTED });
  });

  it('patches every data-bearing method', (): void => {
    const target = makeFakeConsole();
    const errorSpy = spyFor(target.error);
    const warnSpy = spyFor(target.warn);
    enableConsoleRedaction({ target });
    target.error({ token: 'abc' });
    target.warn({ secret: 's' });
    expect(errorSpy).toHaveBeenCalledWith({ token: DEFAULT_REDACTED });
    expect(warnSpy).toHaveBeenCalledWith({ secret: DEFAULT_REDACTED });
  });

  it('leaves primitive arguments unchanged', (): void => {
    const target = makeFakeConsole();
    const logSpy = spyFor(target.log);
    enableConsoleRedaction({ target });
    target.log('plain string', 42, true);
    expect(logSpy).toHaveBeenCalledWith('plain string', 42, true);
  });

  it('uses a supplied redactor', (): void => {
    const target = makeFakeConsole();
    const logSpy = spyFor(target.log);
    const redactor = new Redactor({ patterns: ['ssn'], replacement: '##' });
    enableConsoleRedaction({ target, redactor });
    target.log({ ssn: '123', password: 'p' });
    expect(logSpy).toHaveBeenCalledWith({ ssn: '##', password: 'p' });
  });

  it('honors a restricted method list and leaves others un-patched', (): void => {
    const target = makeFakeConsole();
    const originalWarn = target.warn;
    const logSpy = spyFor(target.log);
    enableConsoleRedaction({ target, methods: ['log'] });
    expect(target.warn).toBe(originalWarn);
    target.log({ password: 'p' });
    expect(logSpy).toHaveBeenCalledWith({ password: DEFAULT_REDACTED });
  });

  it('skips methods that are not functions on the target', (): void => {
    const target = { log: vi.fn(), table: undefined } as unknown as Console;
    const logSpy = spyFor(target.log);
    expect((): void => {
      enableConsoleRedaction({ target, methods: ['log', 'table'] });
    }).not.toThrow();
    target.log({ password: 'p' });
    expect(logSpy).toHaveBeenCalledWith({ password: DEFAULT_REDACTED });
  });

  it('never throws when the redactor fails, forwarding the original argument', (): void => {
    const target = makeFakeConsole();
    const logSpy = spyFor(target.log);
    const throwing = {
      redact(): unknown {
        throw new Error('boom');
      }
    } as unknown as Redactor;
    enableConsoleRedaction({ target, redactor: throwing });
    const payload = { password: 'p' };
    expect((): void => {
      target.log(payload);
    }).not.toThrow();
    expect(logSpy).toHaveBeenCalledWith(payload);
  });
});

describe('disableConsoleRedaction', () => {
  it('restores the original methods', (): void => {
    const target = makeFakeConsole();
    const originalLog = target.log;
    enableConsoleRedaction({ target });
    expect(target.log).not.toBe(originalLog);
    disableConsoleRedaction();
    expect(target.log).toBe(originalLog);
  });

  it('is a no-op when redaction is not enabled', (): void => {
    expect((): void => {
      disableConsoleRedaction();
    }).not.toThrow();
    expect(isConsoleRedactionEnabled()).toBe(false);
  });

  it('is also reachable via the returned restore function', (): void => {
    const target = makeFakeConsole();
    const originalLog = target.log;
    const restore = enableConsoleRedaction({ target });
    restore();
    expect(target.log).toBe(originalLog);
  });
});

describe('enableConsoleRedaction - re-entry', () => {
  it('replaces a prior patch so a single disable fully restores', (): void => {
    const target = makeFakeConsole();
    const originalLog = target.log;
    enableConsoleRedaction({ target });
    enableConsoleRedaction({ target });
    disableConsoleRedaction();
    expect(target.log).toBe(originalLog);
  });

  it('reports the enabled state', (): void => {
    const target = makeFakeConsole();
    expect(isConsoleRedactionEnabled()).toBe(false);
    enableConsoleRedaction({ target });
    expect(isConsoleRedactionEnabled()).toBe(true);
    disableConsoleRedaction();
    expect(isConsoleRedactionEnabled()).toBe(false);
  });
});

describe('enableConsoleRedaction - default target', () => {
  it('patches the global console', (): void => {
    const spy = vi.spyOn(console, 'log').mockImplementation((): void => {
      /* swallow output during the test */
    });
    enableConsoleRedaction();
    console.log({ password: 'p' });
    expect(spy).toHaveBeenCalledWith({ password: DEFAULT_REDACTED });
    disableConsoleRedaction();
    spy.mockRestore();
  });
});
