import { bench, describe } from 'vitest';
// fast-redact ships no types; it is a dev-only benchmark dependency.
import fastRedact from 'fast-redact';
import { Redactor } from '../src/Redactor';

/**
 * The paths fast-redact must be told about up front. deep-redact needs no
 * paths - it matches these key names anywhere by its default patterns.
 */
const SENSITIVE_PATHS = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.body.password',
  'user.apiKey'
];
const DEEP_PATHS = ['a.b.c.d.e.f.password', 'a.b.c.d.e.f.apiKey', 'a.b.c.d.e.f.token'];

function makeRecord(): Record<string, unknown> {
  return {
    level: 'info',
    msg: 'request completed',
    req: {
      method: 'POST',
      url: '/api/login',
      headers: {
        'content-type': 'application/json',
        cookie: 'session=abc123',
        authorization: 'Bearer xyz.jwt.token'
      },
      body: { username: 'ada', password: 'hunter2' }
    },
    res: { status: 200, durationMs: 42 },
    user: { id: 7, name: 'Ada Lovelace', apiKey: 'sk_live_deadbeef' }
  };
}

function makeLarge(): Record<string, unknown> {
  return {
    ...makeRecord(),
    items: Array.from({ length: 250 }, (_unused, index) => {
      return { id: index, name: `item-${index}`, meta: { note: 'ok', tags: ['a', 'b', 'c'] } };
    })
  };
}

// Several secrets buried at depth 7 (a.b.c.d.e.f.<key>), plus benign siblings.
function makeDeep(): Record<string, unknown> {
  return {
    a: {
      b: { c: { d: { e: { f: { password: 'p', apiKey: 'k', token: 't', keep: 1, note: 'x' } } } } }
    }
  };
}

// Pristine inputs for non-mutating contenders (they never change these).
const small = makeRecord();
const large = makeLarge();
const deep = makeDeep();
// Separate inputs for destructive contenders (per-call work is constant whether
// or not the value is already redacted, so they can safely share these).
const smallD = makeRecord();
const largeD = makeLarge();
const deepD = makeDeep();

const rrAll = new Redactor();
const rrPaths = new Redactor({ paths: SENSITIVE_PATHS });
const rrDeepPaths = new Redactor({ paths: DEEP_PATHS });
const rrMutate = new Redactor({ paths: SENSITIVE_PATHS, mutate: true });
const rrDeepMutate = new Redactor({ paths: DEEP_PATHS, mutate: true });
const rrCompiled = new Redactor({ paths: SENSITIVE_PATHS, mutate: true, compile: true });
const rrDeepCompiled = new Redactor({ paths: DEEP_PATHS, mutate: true, compile: true });

const fr = fastRedact({ paths: SENSITIVE_PATHS, serialize: false });
const frDeep = fastRedact({ paths: DEEP_PATHS, serialize: false });

describe('small record -> object', () => {
  // Destructive (no restore) - fair peer of rr mutate/compile.
  bench('fast-redact (destructive)', () => {
    fr(smallD);
  });
  // Non-destructive (redact + restore) - fair peer of rr all/paths.
  bench('fast-redact (+restore)', () => {
    fr(small);
    fr.restore(small);
  });
  bench('deep-redact (all)', () => {
    rrAll.redact(small);
  });
  bench('deep-redact (registered paths)', () => {
    rrPaths.redact(small);
  });
  bench('deep-redact (mutate)', () => {
    rrMutate.redact(smallD);
  });
  bench('deep-redact (compile)', () => {
    rrCompiled.redact(smallD);
  });
});

describe('large record, few secrets -> object', () => {
  bench('fast-redact (destructive)', () => {
    fr(largeD);
  });
  bench('fast-redact (+restore)', () => {
    fr(large);
    fr.restore(large);
  });
  bench('deep-redact (all)', () => {
    rrAll.redact(large);
  });
  bench('deep-redact (registered paths)', () => {
    rrPaths.redact(large);
  });
  bench('deep-redact (mutate)', () => {
    rrMutate.redact(largeD);
  });
  bench('deep-redact (compile)', () => {
    rrCompiled.redact(largeD);
  });
});

describe('several secrets at depth 7 -> object', () => {
  bench('fast-redact (destructive)', () => {
    frDeep(deepD);
  });
  bench('fast-redact (+restore)', () => {
    frDeep(deep);
    frDeep.restore(deep);
  });
  bench('deep-redact (all)', () => {
    rrAll.redact(deep);
  });
  bench('deep-redact (registered paths)', () => {
    rrDeepPaths.redact(deep);
  });
  bench('deep-redact (mutate)', () => {
    rrDeepMutate.redact(deepD);
  });
  bench('deep-redact (compile)', () => {
    rrDeepCompiled.redact(deepD);
  });
});
