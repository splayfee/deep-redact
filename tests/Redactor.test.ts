import { describe, expect, it } from 'vitest';
import { Redactor } from '../src/Redactor';
import {
  CIRCULAR_MARKER,
  DEFAULT_MAX_DEPTH,
  DEFAULT_REDACTED,
  DEFAULT_SENSITIVE_KEY_PATTERNS,
  TRUNCATED_MARKER
} from '../src/constants';

describe('Redactor - default pattern matching', () => {
  it('redacts each default sensitive key name', (): void => {
    const redactor = new Redactor();
    const keys = [
      'password',
      'passwd',
      'pwd',
      'secret',
      'token',
      'accessToken',
      'refresh_token',
      'apiKey',
      'api_key',
      'API-KEY',
      'accessKeyId',
      'secretAccessKey',
      'authorization',
      'authToken',
      'cookie',
      'setCookie',
      'sessionId',
      'credential',
      'credentials',
      'privateKey'
    ];
    for (const key of keys) {
      const result = redactor.redact({ [key]: 'super-secret' }) as Record<string, unknown>;
      expect(result[key]).toBe(DEFAULT_REDACTED);
    }
  });

  it('leaves non-sensitive keys untouched, including near-misses', (): void => {
    const redactor = new Redactor();
    const input = {
      username: 'alice',
      id: 42,
      tokenCount: 7,
      description: 'a token is mentioned here',
      passwordHint: 'not the password itself'
    };
    expect(redactor.redact(input)).toEqual(input);
  });

  it('matches case-insensitively by default', (): void => {
    const redactor = new Redactor();
    const result = redactor.redact({ PASSWORD: 'x', Secret: 'y' }) as Record<string, unknown>;
    expect(result).toEqual({ PASSWORD: DEFAULT_REDACTED, Secret: DEFAULT_REDACTED });
  });
});

describe('Redactor - traversal', () => {
  it('redacts sensitive keys at any nesting depth', (): void => {
    const redactor = new Redactor();
    const input = {
      user: { name: 'bob', credentials: { password: 'hunter2' } },
      tokens: [{ token: 'abc' }, { token: 'def' }]
    };
    const result = redactor.redact(input);
    expect(result).toEqual({
      user: { name: 'bob', credentials: DEFAULT_REDACTED },
      tokens: [{ token: DEFAULT_REDACTED }, { token: DEFAULT_REDACTED }]
    });
  });

  it('redacts secrets nested 7 levels deep (within default maxDepth)', (): void => {
    const redactor = new Redactor();
    const input = { a: { b: { c: { d: { e: { f: { password: 'p', apiKey: 'k', keep: 1 } } } } } } };
    expect(redactor.redact(input)).toEqual({
      a: {
        b: {
          c: { d: { e: { f: { password: DEFAULT_REDACTED, apiKey: DEFAULT_REDACTED, keep: 1 } } } }
        }
      }
    });
  });

  it('recurses into Map values and redacts by string key', (): void => {
    const redactor = new Redactor();
    const input = new Map<unknown, unknown>([
      ['password', 'hunter2'],
      ['nested', { token: 'abc', keep: 1 }],
      [7, { secret: 's' }]
    ]);
    const result = redactor.redact(input) as Map<unknown, unknown>;
    expect(result).toBeInstanceOf(Map);
    expect(result.get('password')).toBe(DEFAULT_REDACTED);
    expect(result.get('nested')).toEqual({ token: DEFAULT_REDACTED, keep: 1 });
    expect(result.get(7)).toEqual({ secret: DEFAULT_REDACTED });
  });

  it('recurses into Set items', (): void => {
    const redactor = new Redactor();
    const input = new Set<unknown>([{ password: 'p' }, { keep: 1 }]);
    const result = redactor.redact(input) as Set<unknown>;
    expect(result).toBeInstanceOf(Set);
    expect([...result]).toEqual([{ password: DEFAULT_REDACTED }, { keep: 1 }]);
  });

  it('handles objects with a null prototype', (): void => {
    const redactor = new Redactor();
    const input = Object.assign(Object.create(null) as Record<string, unknown>, {
      password: 'p',
      keep: 1
    });
    expect(redactor.redact(input)).toEqual({ password: DEFAULT_REDACTED, keep: 1 });
  });
});

describe('Redactor - pass-through values', () => {
  it('returns primitives unchanged', (): void => {
    const redactor = new Redactor();
    expect(redactor.redact('hello')).toBe('hello');
    expect(redactor.redact(123)).toBe(123);
    expect(redactor.redact(true)).toBe(true);
    expect(redactor.redact(null)).toBeNull();
    expect(redactor.redact(undefined)).toBeUndefined();
  });

  it('leaves Date, RegExp, and class instances as-is (by reference)', (): void => {
    const redactor = new Redactor();
    const date = new Date(0);
    const regex = /abc/;
    class Widget {
      public password = 'p';
    }
    const widget = new Widget();
    expect(redactor.redact(date)).toBe(date);
    expect(redactor.redact(regex)).toBe(regex);
    // Class instances are not plain objects, so they pass through untouched.
    expect(redactor.redact(widget)).toBe(widget);
  });

  it('leaves functions untouched', (): void => {
    const redactor = new Redactor();
    const fn = (): number => {
      return 1;
    };
    expect(redactor.redact(fn)).toBe(fn);
  });
});

describe('Redactor - safety', () => {
  it('does not mutate the input', (): void => {
    const redactor = new Redactor();
    const input = { password: 'p', nested: { token: 't' } };
    const snapshot = structuredClone(input);
    redactor.redact(input);
    expect(input).toEqual(snapshot);
  });

  it('replaces circular references with a marker instead of recursing forever', (): void => {
    const redactor = new Redactor();
    const input: Record<string, unknown> = { name: 'root', password: 'p' };
    input.self = input;
    const result = redactor.redact(input) as Record<string, unknown>;
    expect(result.name).toBe('root');
    expect(result.password).toBe(DEFAULT_REDACTED);
    expect(result.self).toBe(CIRCULAR_MARKER);
  });

  it('does not flag a shared (non-cyclic) reference as circular', (): void => {
    const redactor = new Redactor();
    const shared = { keep: 1 };
    const input = { a: shared, b: shared };
    const result = redactor.redact(input);
    expect(result).toEqual({ a: { keep: 1 }, b: { keep: 1 } });
  });

  it('truncates values nested deeper than maxDepth', (): void => {
    const redactor = new Redactor({ maxDepth: 2 });
    const input = { a: { b: { c: { d: 'deep' } } } };
    const result = redactor.redact(input) as Record<string, Record<string, unknown>>;
    expect(result.a.b).toEqual({ c: TRUNCATED_MARKER });
  });

  it('exposes the default max depth constant', (): void => {
    expect(DEFAULT_MAX_DEPTH).toBe(8);
  });
});

describe('Redactor - mutating the match list', () => {
  it('add() introduces a new pattern and is chainable', (): void => {
    const redactor = new Redactor({ patterns: [] });
    const returned = redactor.add('ssn');
    expect(returned).toBe(redactor);
    expect(redactor.redact({ ssn: '123', keep: 1 })).toEqual({ ssn: DEFAULT_REDACTED, keep: 1 });
  });

  it('add() ignores duplicates', (): void => {
    const redactor = new Redactor({ patterns: ['token'] });
    redactor.add('token', 'token');
    expect(redactor.getPatterns()).toEqual(['token']);
  });

  it('remove() drops a pattern so the key is no longer redacted', (): void => {
    const redactor = new Redactor();
    redactor.remove('cookie');
    expect(redactor.has('cookie')).toBe(false);
    expect(redactor.redact({ cookie: 'c' })).toEqual({ cookie: 'c' });
  });

  it('remove() ignores unknown patterns', (): void => {
    const redactor = new Redactor({ patterns: ['token'] });
    redactor.remove('does-not-exist');
    expect(redactor.getPatterns()).toEqual(['token']);
  });

  it('replace() swaps the entire list', (): void => {
    const redactor = new Redactor();
    redactor.replace(['ssn', 'dob']);
    expect(redactor.getPatterns()).toEqual(['ssn', 'dob']);
    expect(redactor.redact({ password: 'p', ssn: '1' })).toEqual({
      password: 'p',
      ssn: DEFAULT_REDACTED
    });
  });

  it('clear() removes every pattern so nothing is redacted', (): void => {
    const redactor = new Redactor();
    redactor.clear();
    expect(redactor.getPatterns()).toEqual([]);
    expect(redactor.redact({ password: 'p' })).toEqual({ password: 'p' });
  });

  it('getPatterns() returns a copy that cannot mutate internal state', (): void => {
    const redactor = new Redactor({ patterns: ['token'] });
    const patterns = redactor.getPatterns();
    patterns.push('injected');
    expect(redactor.getPatterns()).toEqual(['token']);
  });

  it('defaults to the shared default pattern list', (): void => {
    const redactor = new Redactor();
    expect(redactor.getPatterns()).toEqual([...DEFAULT_SENSITIVE_KEY_PATTERNS]);
  });
});

describe('Redactor - options', () => {
  it('honors a custom replacement string', (): void => {
    const redactor = new Redactor({ replacement: '***' });
    expect(redactor.redact({ password: 'p' })).toEqual({ password: '***' });
  });

  it('supports case-sensitive matching', (): void => {
    const redactor = new Redactor({ patterns: ['token'], caseSensitive: true });
    const result = redactor.redact({ token: 'a', TOKEN: 'b' });
    expect(result).toEqual({ token: DEFAULT_REDACTED, TOKEN: 'b' });
  });

  it('supports substring matching when matchWholeKey is false', (): void => {
    const redactor = new Redactor({ patterns: ['token'], matchWholeKey: false });
    const result = redactor.redact({ tokenCount: 5, authToken: 'x' });
    expect(result).toEqual({ tokenCount: DEFAULT_REDACTED, authToken: DEFAULT_REDACTED });
  });

  it('matches nothing when constructed with an empty pattern list', (): void => {
    const redactor = new Redactor({ patterns: [] });
    expect(redactor.regex.test('password')).toBe(false);
    expect(redactor.redact({ password: 'p' })).toEqual({ password: 'p' });
  });

  it('removes the matched key entirely when removeMatched is true', (): void => {
    const redactor = new Redactor({ removeMatched: true });
    const result = redactor.redact({ password: 'p', keep: 1 }) as Record<string, unknown>;
    expect(result).toEqual({ keep: 1 });
    expect('password' in result).toBe(false);
  });

  it('drops matched Map entries when removeMatched is true', (): void => {
    const redactor = new Redactor({ removeMatched: true });
    const input = new Map<unknown, unknown>([
      ['token', 'abc'],
      ['keep', 1]
    ]);
    const result = redactor.redact(input) as Map<unknown, unknown>;
    expect(result.has('token')).toBe(false);
    expect(result.get('keep')).toBe(1);
  });

  it('removes matched keys at any nesting depth', (): void => {
    const redactor = new Redactor({ removeMatched: true });
    const input = { user: { name: 'bob', password: 'p' }, items: [{ token: 't', id: 1 }] };
    expect(redactor.redact(input)).toEqual({ user: { name: 'bob' }, items: [{ id: 1 }] });
  });

  it('ignores removeMatched for non-keyed containers (arrays, sets)', (): void => {
    const redactor = new Redactor({ patterns: ['password'], removeMatched: true });
    const input = { list: ['a', 'b'], set: new Set([1, 2]) };
    const result = redactor.redact(input) as { list: unknown[]; set: Set<unknown> };
    expect(result.list).toEqual(['a', 'b']);
    expect([...result.set]).toEqual([1, 2]);
  });
});

describe('Redactor - regex accessor', () => {
  it('recompiles when the pattern list changes', (): void => {
    const redactor = new Redactor({ patterns: ['token'] });
    expect(redactor.regex.test('token')).toBe(true);
    expect(redactor.regex.test('ssn')).toBe(false);
    redactor.add('ssn');
    expect(redactor.regex.test('ssn')).toBe(true);
  });
});

describe('Redactor - input validation', () => {
  it('throws when a pattern is not a non-empty string', (): void => {
    expect((): void => {
      new Redactor({ patterns: [''] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ patterns: [123 as unknown as string] });
    }).toThrow(TypeError);
  });

  it('throws when a pattern is not a valid regular expression', (): void => {
    expect((): void => {
      new Redactor({ patterns: ['('] });
    }).toThrow(SyntaxError);
  });

  it('throws when patterns is not an array', (): void => {
    expect((): void => {
      new Redactor({ patterns: 'password' as unknown as string[] });
    }).toThrow(TypeError);
  });

  it('throws when maxDepth is negative or non-integer', (): void => {
    expect((): void => {
      new Redactor({ maxDepth: -1 });
    }).toThrow(RangeError);
    expect((): void => {
      new Redactor({ maxDepth: 1.5 });
    }).toThrow(RangeError);
  });

  it('throws when replacement is not a string', (): void => {
    expect((): void => {
      new Redactor({ replacement: 5 as unknown as string });
    }).toThrow(TypeError);
  });

  it('surfaces an invalid pattern added later', (): void => {
    const redactor = new Redactor({ patterns: [] });
    expect((): void => {
      redactor.add('[');
    }).toThrow(SyntaxError);
  });
});
