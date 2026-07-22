import { describe, expect, it } from 'vitest';
import { Redactor } from '../src/Redactor';
import { RedactionReason } from '../src/types';
import type { Censor, RedactionContext } from '../src/types';
import { DEFAULT_REDACTED } from '../src/constants';
import { compilePathFunction } from '../src/codegen';

describe('valuePatterns - content redaction', () => {
  it('censors a matching substring in a string value, leaving the rest', (): void => {
    const redactor = new Redactor({ patterns: [], valuePatterns: ['\\d{3}-\\d{2}-\\d{4}'] });
    expect(redactor.redact({ note: 'ssn 123-45-6789 end' })).toEqual({
      note: `ssn ${DEFAULT_REDACTED} end`
    });
  });

  it('accepts a RegExp and redacts a top-level string', (): void => {
    const redactor = new Redactor({ patterns: [], valuePatterns: [/\d{3}-\d{2}-\d{4}/] });
    expect(redactor.redact('ssn 123-45-6789')).toBe(`ssn ${DEFAULT_REDACTED}`);
  });

  it('scans values inside arrays, Sets, and Maps', (): void => {
    const redactor = new Redactor({ patterns: [], valuePatterns: ['secret\\d'] });
    expect(redactor.redact(['secret1', 'ok'])).toEqual([DEFAULT_REDACTED, 'ok']);
    expect([...(redactor.redact(new Set(['secret2', 'keep'])) as Set<unknown>)]).toEqual([
      DEFAULT_REDACTED,
      'keep'
    ]);
    const map = redactor.redact(new Map([['note', 'secret3']])) as Map<unknown, unknown>;
    expect(map.get('note')).toBe(DEFAULT_REDACTED);
  });

  it('honors caseSensitive for value patterns', (): void => {
    expect(new Redactor({ patterns: [], valuePatterns: ['secret'] }).redact('SECRET')).toBe(
      DEFAULT_REDACTED
    );
    const strict = new Redactor({ patterns: [], valuePatterns: ['secret'], caseSensitive: true });
    expect(strict.redact('SECRET')).toBe('SECRET');
  });

  it('leaves strings untouched when no value patterns are configured', (): void => {
    expect(new Redactor().redact('123-45-6789')).toBe('123-45-6789');
  });
});

describe('replacement as a censor function', () => {
  it('supports partial masking', (): void => {
    const mask: Censor = (value): unknown => {
      return typeof value === 'string' ? `****${value.slice(-4)}` : DEFAULT_REDACTED;
    };
    expect(new Redactor({ replacement: mask }).redact({ password: 'hunter2' })).toEqual({
      password: '****ter2'
    });
  });

  it('passes key, path, and matchedBy for a key match', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact({ user: { password: 'p' } });
    expect(seen[0].key).toBe('password');
    expect(seen[0].path).toEqual(['user', 'password']);
    expect(seen[0].matchedBy).toBe(RedactionReason.Key);
  });

  it('reports matchedBy=value and a null key for a value match', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      patterns: [],
      valuePatterns: ['\\d{4}'],
      replacement: (_value, context): string => {
        seen.push(context);
        return '#';
      }
    });
    redactor.redact({ note: 'pin 1234' });
    expect(seen[0].key).toBeNull();
    expect(seen[0].matchedBy).toBe(RedactionReason.Value);
  });
});

describe('paths - targeted redaction', () => {
  it('redacts an exact dotted path only', (): void => {
    const redactor = new Redactor({ patterns: [], paths: ['a.b'] });
    expect(redactor.redact({ a: { b: 'secret', c: 1 }, b: 'keep' })).toEqual({
      a: { b: DEFAULT_REDACTED, c: 1 },
      b: 'keep'
    });
  });

  it('supports single-level wildcards', (): void => {
    const redactor = new Redactor({ patterns: [], paths: ['*.token'] });
    expect(redactor.redact({ x: { token: 't' }, y: { token: 'u' }, token: 'top' })).toEqual({
      x: { token: DEFAULT_REDACTED },
      y: { token: DEFAULT_REDACTED },
      token: 'top'
    });
  });

  it('targets array elements by index and wildcard', (): void => {
    const byIndex = new Redactor({ patterns: [], paths: ['tokens[0]'] });
    expect(byIndex.redact({ tokens: ['a', 'b'] })).toEqual({ tokens: [DEFAULT_REDACTED, 'b'] });

    const byWildcard = new Redactor({ patterns: [], paths: ['items[*].secret'] });
    expect(
      byWildcard.redact({
        items: [
          { secret: 'a', id: 1 },
          { secret: 'b', id: 2 }
        ]
      })
    ).toEqual({
      items: [
        { secret: DEFAULT_REDACTED, id: 1 },
        { secret: DEFAULT_REDACTED, id: 2 }
      ]
    });
  });

  it('supports quoted bracket keys', (): void => {
    const redactor = new Redactor({ patterns: [], paths: ['headers["x-api-key"]'] });
    expect(redactor.redact({ headers: { 'x-api-key': 'k', ok: 1 } })).toEqual({
      headers: { 'x-api-key': DEFAULT_REDACTED, ok: 1 }
    });
  });

  it('reports matchedBy=path to the censor', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      patterns: [],
      paths: ['a.b'],
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact({ a: { b: 1 } });
    expect(seen[0].matchedBy).toBe(RedactionReason.Path);
  });

  it('tracks the path through Map string keys', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact({ creds: new Map<unknown, unknown>([['password', 'p']]) });
    expect(seen[0].path).toEqual(['creds', 'password']);
  });

  it('tracks the path through class-instance keys', (): void => {
    const seen: RedactionContext[] = [];
    class User {
      public password = 'p';
    }
    const redactor = new Redactor({
      redactInstances: true,
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact({ user: new User() });
    expect(seen[0].path).toEqual(['user', 'password']);
  });
});

describe('registered paths - fast mode edge cases', () => {
  it('ignores key and value patterns in path mode', (): void => {
    const redactor = new Redactor({ paths: ['a.b'] });
    expect(redactor.redact({ password: 'p', a: { b: 'secret', c: 1 } })).toEqual({
      password: 'p',
      a: { b: DEFAULT_REDACTED, c: 1 }
    });
  });

  it('removes a matched key in path mode with removeMatched', (): void => {
    const redactor = new Redactor({ paths: ['a.b'], removeMatched: true });
    const result = redactor.redact({ a: { b: 'x', c: 1 } }) as { a: Record<string, unknown> };
    expect(result.a).toEqual({ c: 1 });
    expect('b' in result.a).toBe(false);
  });

  it('returns the same reference when a registered path is absent', (): void => {
    const redactor = new Redactor({ paths: ['x.y'] });
    const input = { x: { z: 1 }, keep: 2 };
    expect(redactor.redact(input)).toBe(input);
  });

  it('shares untouched subtrees in path mode', (): void => {
    const redactor = new Redactor({ paths: ['a.b'] });
    const input = { a: { b: 'secret' }, other: { deep: 1 } };
    const result = redactor.redact(input) as { other: unknown };
    expect(result).not.toBe(input);
    expect(result.other).toBe(input.other);
  });

  it('ignores an out-of-range array index', (): void => {
    const redactor = new Redactor({ paths: ['t[5]'] });
    const input = { t: ['a', 'b'] };
    expect(redactor.redact(input)).toBe(input);
  });

  it('leaves array elements without the wildcard subpath untouched', (): void => {
    const redactor = new Redactor({ paths: ['items[*].secret'] });
    const result = redactor.redact({ items: [{ secret: 'a' }, { id: 1 }] }) as {
      items: Record<string, unknown>[];
    };
    expect(result.items[0]).toEqual({ secret: DEFAULT_REDACTED });
    expect(result.items[1]).toEqual({ id: 1 });
  });

  it('sets an array element to undefined in path mode with removeMatched', (): void => {
    const redactor = new Redactor({ paths: ['t[0]'], removeMatched: true });
    expect(redactor.redact({ t: ['a', 'b'] })).toEqual({ t: [undefined, 'b'] });
  });

  it('mutates in place and returns the same reference when mutate is true', (): void => {
    const redactor = new Redactor({ paths: ['a.b'], mutate: true });
    const input = { a: { b: 'secret', c: 1 } };
    const result = redactor.redact(input);
    expect(result).toBe(input);
    expect(input.a.b).toBe(DEFAULT_REDACTED);
    expect(input.a.c).toBe(1);
  });

  it('mutates arrays and removes keys in place', (): void => {
    const arr = new Redactor({ paths: ['t[0]'], mutate: true });
    const arrInput = { t: ['a', 'b'] };
    expect(arr.redact(arrInput)).toBe(arrInput);
    expect(arrInput.t[0]).toBe(DEFAULT_REDACTED);

    const rm = new Redactor({ paths: ['a.b'], mutate: true, removeMatched: true });
    const rmInput: { a: Record<string, unknown> } = { a: { b: 'x', c: 1 } };
    rm.redact(rmInput);
    expect('b' in rmInput.a).toBe(false);
    expect(rmInput.a.c).toBe(1);
  });

  it('ignores mutate during the full walk (stays immutable)', (): void => {
    const redactor = new Redactor({ mutate: true });
    const input = { password: 'p' };
    const result = redactor.redact(input);
    expect(result).not.toBe(input);
    expect(input.password).toBe('p');
  });

  it('redacts via the interpreted flat fast path (mutate, literal paths)', (): void => {
    const redactor = new Redactor({ paths: ['a.b', 'x'], mutate: true });
    const input = { a: { b: 'secret', c: 1 }, x: 'gone', keep: 2 };
    const result = redactor.redact(input);
    expect(result).toBe(input);
    expect(input.a.b).toBe(DEFAULT_REDACTED);
    expect(input.x).toBe(DEFAULT_REDACTED);
    expect(input.a.c).toBe(1);
    expect(input.keep).toBe(2);
  });

  it('flat fast path ignores absent paths and non-object roots', (): void => {
    const redactor = new Redactor({ paths: ['a.b'], mutate: true });
    expect(redactor.redact('scalar')).toBe('scalar');
    const partial = { a: 'not-an-object' };
    expect(redactor.redact(partial)).toBe(partial);
  });

  it('flat fast path supports a censor function and removeMatched', (): void => {
    const seen: RedactionContext[] = [];
    const fn = new Redactor({
      paths: ['a.b'],
      mutate: true,
      replacement: (_value, context): string => {
        seen.push(context);
        return '#';
      }
    });
    const input = { a: { b: 'secret' } };
    fn.redact(input);
    expect(input.a.b).toBe('#');
    expect(seen[0].matchedBy).toBe(RedactionReason.Path);

    const rm = new Redactor({ paths: ['a.b'], mutate: true, removeMatched: true });
    const rmInput: { a: Record<string, unknown> } = { a: { b: 'x', c: 1 } };
    rm.redact(rmInput);
    expect('b' in rmInput.a).toBe(false);
    expect(rmInput.a.c).toBe(1);
  });

  it('redacts via compiled codegen (compile + mutate + literal paths)', (): void => {
    const redactor = new Redactor({ paths: ['a.b', 'x'], mutate: true, compile: true });
    const input = { a: { b: 'secret', c: 1 }, x: 'gone' };
    const result = redactor.redact(input);
    expect(result).toBe(input);
    expect(input.a.b).toBe(DEFAULT_REDACTED);
    expect(input.x).toBe(DEFAULT_REDACTED);
    expect(input.a.c).toBe(1);
  });

  it('compiled codegen honors removeMatched and skips absent paths', (): void => {
    const redactor = new Redactor({
      paths: ['a.b', 'z.y'],
      mutate: true,
      compile: true,
      removeMatched: true
    });
    const input: { a: Record<string, unknown> } = { a: { b: 'x', c: 1 } };
    redactor.redact(input);
    expect('b' in input.a).toBe(false);
    expect(input.a.c).toBe(1);
  });

  it('does not compile with wildcards or a censor function (falls back)', (): void => {
    const wild = new Redactor({ paths: ['*.b'], mutate: true, compile: true });
    expect(wild.redact({ a: { b: 'secret' } })).toEqual({ a: { b: DEFAULT_REDACTED } });

    const fn = new Redactor({
      paths: ['a.b'],
      mutate: true,
      compile: true,
      replacement: (): string => {
        return '#';
      }
    });
    const input = { a: { b: 'secret' } };
    fn.redact(input);
    expect(input.a.b).toBe('#');
  });

  it('flat fast path stops at a non-object mid-segment and skips absent leaves', (): void => {
    const deep = new Redactor({ paths: ['a.b.c'], mutate: true });
    const midInput = { a: 'x' };
    expect(deep.redact(midInput)).toBe(midInput);
    expect(midInput.a).toBe('x');

    const leaf = new Redactor({ paths: ['a.missing'], mutate: true });
    const leafInput = { a: { other: 1 } };
    leaf.redact(leafInput);
    expect(leafInput.a).toEqual({ other: 1 });
  });

  it('treats a degenerate path as a no-op', (): void => {
    const redactor = new Redactor({ paths: ['.'], mutate: true });
    const input = { a: 1 };
    expect(redactor.redact(input)).toBe(input);
  });

  it('merges shared path prefixes (literal and wildcard)', (): void => {
    const literal = new Redactor({ paths: ['a.b', 'a.c'] });
    expect(literal.redact({ a: { b: 1, c: 2, d: 3 } })).toEqual({
      a: { b: DEFAULT_REDACTED, c: DEFAULT_REDACTED, d: 3 }
    });
    const wild = new Redactor({ paths: ['*.a', '*.b'] });
    expect(wild.redact({ x: { a: 1, b: 2, c: 3 } })).toEqual({
      x: { a: DEFAULT_REDACTED, b: DEFAULT_REDACTED, c: 3 }
    });
  });
});

describe('stringify', () => {
  it('redacts and serializes in one call', (): void => {
    const redactor = new Redactor();
    expect(redactor.stringify({ user: 'ada', password: 'p' })).toBe(
      `{"user":"ada","password":"${DEFAULT_REDACTED}"}`
    );
  });

  it('supports pretty-print spacing', (): void => {
    const redactor = new Redactor();
    expect(redactor.stringify({ password: 'p' }, 2)).toBe(
      `{\n  "password": "${DEFAULT_REDACTED}"\n}`
    );
  });

  it('serializes the output of registered-paths mutate mode', (): void => {
    const redactor = new Redactor({ paths: ['a.b'], mutate: true });
    expect(redactor.stringify({ a: { b: 'secret', c: 1 } })).toBe(
      `{"a":{"b":"${DEFAULT_REDACTED}","c":1}}`
    );
  });
});

describe('codegen fallback', () => {
  it('returns null when there is no literal replacement and no removeMatched', (): void => {
    expect(compilePathFunction([['a']], null, false)).toBeNull();
  });

  it('returns null when new Function is blocked (strict CSP)', (): void => {
    const holder = globalThis as unknown as { Function: unknown };
    const original = holder.Function;
    try {
      holder.Function = function (): never {
        throw new Error('unsafe-eval blocked');
      };
      expect(compilePathFunction([['a']], DEFAULT_REDACTED, false)).toBeNull();
    } finally {
      holder.Function = original;
    }
  });
});

describe('independent instances', () => {
  it('a default full-walk redactor and a registered-paths redactor do not interfere', (): void => {
    const general = new Redactor(); // e.g. the console redactor: default patterns, immutable
    const csv = new Redactor({ paths: ['user.ssn'], mutate: true }); // hot path, in place

    const record = { user: { ssn: '123-45-6789', password: 'p' }, note: 'ok' };

    const logged = general.redact(record) as { user: Record<string, unknown> };
    expect(logged.user.password).toBe(DEFAULT_REDACTED); // 'password' is a default key
    expect(logged.user.ssn).toBe('123-45-6789'); // 'ssn' is not; general leaves it
    expect(record.user.password).toBe('p'); // general never mutates its input

    csv.redact(record);
    expect(record.user.ssn).toBe(DEFAULT_REDACTED); // path-redacted, in place
    expect(record.user.password).toBe('p'); // csv ignores key patterns entirely
  });
});

describe('copy-on-write reuse (multiple redactions per container)', () => {
  it('reuses the clone across multiple censored object keys', (): void => {
    const redactor = new Redactor();
    expect(redactor.redact({ password: 'p', token: 't', keep: 1 })).toEqual({
      password: DEFAULT_REDACTED,
      token: DEFAULT_REDACTED,
      keep: 1
    });
  });

  it('reuses the clone across multiple removed object keys', (): void => {
    const redactor = new Redactor({ removeMatched: true });
    expect(redactor.redact({ password: 'p', token: 't', keep: 1 })).toEqual({ keep: 1 });
  });

  it('reuses the clone across multiple censored Map keys', (): void => {
    const redactor = new Redactor();
    const input = new Map<unknown, unknown>([
      ['password', 'p'],
      ['token', 't'],
      ['keep', 1]
    ]);
    const result = redactor.redact(input) as Map<unknown, unknown>;
    expect(result.get('password')).toBe(DEFAULT_REDACTED);
    expect(result.get('token')).toBe(DEFAULT_REDACTED);
    expect(result.get('keep')).toBe(1);
  });

  it('reuses the clone across multiple removed Map keys', (): void => {
    const redactor = new Redactor({ removeMatched: true });
    const input = new Map<unknown, unknown>([
      ['password', 'p'],
      ['token', 't'],
      ['keep', 1]
    ]);
    const result = redactor.redact(input) as Map<unknown, unknown>;
    expect(result.has('password')).toBe(false);
    expect(result.has('token')).toBe(false);
    expect(result.get('keep')).toBe(1);
  });
});

describe('censor context through arrays and Maps (full walk)', () => {
  it('tracks array indices in the path', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact({ list: [{ password: 'p' }] });
    expect(seen[0].path).toEqual(['list', 0, 'password']);
  });

  it('tracks Map keys when recursing through non-sensitive entries', (): void => {
    const seen: RedactionContext[] = [];
    const redactor = new Redactor({
      replacement: (_value, context): string => {
        seen.push(context);
        return DEFAULT_REDACTED;
      }
    });
    redactor.redact(new Map<unknown, unknown>([['data', { password: 'p' }]]));
    expect(seen[0].path).toEqual(['data', 'password']);
  });
});

describe('redactInstances - Errors and class instances', () => {
  it('passes Errors and class instances through by reference when disabled', (): void => {
    const error = new Error('boom');
    expect(new Redactor().redact(error)).toBe(error);
  });

  it('copies an Error to a plain object with essentials and censored keys', (): void => {
    const redactor = new Redactor({ redactInstances: true });
    const error = new Error('boom') as Error & Record<string, unknown>;
    error.password = 'p';
    error.config = { headers: { authorization: 'Bearer x' } };
    const result = redactor.redact(error) as Record<string, unknown>;
    expect(result.name).toBe('Error');
    expect(result.message).toBe('boom');
    expect(typeof result.stack).toBe('string');
    expect(result.password).toBe(DEFAULT_REDACTED);
    expect(result.config).toEqual({ headers: { authorization: DEFAULT_REDACTED } });
  });

  it('value-scans an Error message and stack', (): void => {
    const redactor = new Redactor({
      patterns: [],
      valuePatterns: ['\\d{16}'],
      redactInstances: true
    });
    const result = redactor.redact(new Error('card 4111111111111111')) as Record<string, unknown>;
    expect(result.message).toBe(`card ${DEFAULT_REDACTED}`);
  });

  it('handles an Error whose stack is absent', (): void => {
    const error = new Error('boom');
    error.stack = undefined;
    const result = new Redactor({ redactInstances: true }).redact(error) as Record<string, unknown>;
    expect(result.message).toBe('boom');
    expect('stack' in result).toBe(false);
  });

  it('redacts a generic class instance', (): void => {
    class User {
      public password = 'p';
      public name = 'ada';
    }
    expect(new Redactor({ redactInstances: true }).redact(new User())).toEqual({
      password: DEFAULT_REDACTED,
      name: 'ada'
    });
  });

  it('removes matched instance keys with removeMatched', (): void => {
    class User {
      public password = 'p';
      public name = 'ada';
    }
    const redactor = new Redactor({ redactInstances: true, removeMatched: true });
    expect(redactor.redact(new User())).toEqual({ name: 'ada' });
  });

  it('still passes Date, RegExp, Promise, WeakMap, ArrayBuffer, and typed arrays through', (): void => {
    const redactor = new Redactor({ redactInstances: true });
    const date = new Date(0);
    const regex = /x/;
    const promise = Promise.resolve(1);
    const weak = new WeakMap();
    const weakSet = new WeakSet();
    const buffer = new ArrayBuffer(8);
    const typed = new Uint8Array([1, 2, 3]);
    const result = redactor.redact({
      date,
      regex,
      promise,
      weak,
      weakSet,
      buffer,
      typed
    }) as Record<string, unknown>;
    expect(result.date).toBe(date);
    expect(result.regex).toBe(regex);
    expect(result.promise).toBe(promise);
    expect(result.weak).toBe(weak);
    expect(result.weakSet).toBe(weakSet);
    expect(result.buffer).toBe(buffer);
    expect(result.typed).toBe(typed);
  });
});

describe('structural sharing (performance)', () => {
  it('returns the same reference when nothing is redacted', (): void => {
    const redactor = new Redactor();
    const input = { a: { b: 1 }, keep: 'ok' };
    expect(redactor.redact(input)).toBe(input);
  });

  it('shares unchanged subtrees but copies changed ancestors', (): void => {
    const redactor = new Redactor();
    const input = { password: 'p', sub: { a: 1 } };
    const result = redactor.redact(input) as { sub: unknown };
    expect(result).not.toBe(input);
    expect(result.sub).toBe(input.sub);
  });

  it('returns the same Map reference when nothing is redacted', (): void => {
    const redactor = new Redactor();
    const input = new Map<unknown, unknown>([
      ['a', 1],
      ['b', 2]
    ]);
    expect(redactor.redact(input)).toBe(input);
  });
});

describe('validation for new options', () => {
  it('rejects a non-array or invalid valuePatterns', (): void => {
    expect((): void => {
      new Redactor({ valuePatterns: 'x' as unknown as string[] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ valuePatterns: [''] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ valuePatterns: [123 as unknown as string] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ valuePatterns: ['('] });
    }).toThrow(SyntaxError);
  });

  it('rejects a non-array or invalid paths', (): void => {
    expect((): void => {
      new Redactor({ paths: 'x' as unknown as string[] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ paths: [''] });
    }).toThrow(TypeError);
    expect((): void => {
      new Redactor({ paths: [7 as unknown as string] });
    }).toThrow(TypeError);
  });

  it('accepts a function replacement', (): void => {
    expect((): void => {
      new Redactor({
        replacement: (): string => {
          return 'x';
        }
      });
    }).not.toThrow();
  });
});
