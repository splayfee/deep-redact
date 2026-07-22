# @edium/deep-redact

Isomorphic, configurable **deep redaction** for logs and payloads. Censors
secrets by **key name** (anywhere, at any depth), by **value pattern** (secrets
embedded in strings), or by **exact path** - and returns a safe copy. It can also
rewire `console.*` so a secret can never reach the console in the first place.

- **Zero dependencies.** Pure standard-library JavaScript.
- **Isomorphic & CSP-safe.** Runs unchanged in **Node** and the **browser**, with
  no `eval` - unless you opt into the `compile` turbo mode.
- **Dual package.** Ships **ESM** and **CommonJS** builds plus type
  declarations, usable from **TypeScript** or **JavaScript**.
- **Safe by default.** Never mutates input; handles cycles, deep nesting,
  `Map`/`Set`, `null`-prototype objects, and `Error`s; never throws at a log site.
- **Fast when it counts.** Registered-path modes rival - and with `compile`,
  _beat_ - `fast-redact`. See [Performance](#performance).

---

## Why use this library over others?

Most redactors make you enumerate exact **paths** up front (e.g. `fast-redact`,
the engine inside pino). That is blazing fast but assumes you already know where
every secret lives. `deep-redact` is built for the opposite, common reality:
**heterogeneous data whose shape you don't control** - request bodies, MQTT
messages, job payloads, third-party errors.

- **Three ways to match, in one library** - by **key name anywhere** (no path
  bookkeeping; `password` is caught however deep it hides), by **value pattern**
  (`valuePatterns` finds JWTs, cards, SSNs embedded in strings), and by **exact
  path** (fast, surgical targeting). Most redactors do only one of the three.
- **CSP-safe by default** - no `eval`/`new Function` unless you explicitly opt in
  to `compile`. `fast-redact` _always_ needs `unsafe-eval` and simply breaks
  under a strict Content-Security-Policy.
- **As fast as it gets** - registered-path modes rival `fast-redact`, and the
  opt-in `compile` mode is **~1.5-2.2x faster** than it (see
  [Performance](#performance)).
- **Immutable by default** - returns a censored copy (copy-on-write structural
  sharing); never mutates your object or needs a `restore()` step. Opt into
  `mutate` only where you want the speed and don't need the original.
- **Handles real-world structures** - `Map`/`Set`, cycles, `null`-prototype
  objects, and (opt-in) `Error`s and class instances, including stack traces.
- **Partial masking** - a censor function enables `****1234` instead of a flat
  marker.
- **Zero dependencies, isomorphic, TypeScript-first**, with a built-in
  `console.*` patch as a last line of defense and a `stringify` redact-to-JSON
  helper.

`fast-redact` still leads on **ecosystem maturity** (it powers pino, with years
of production use). If you only ever redact a fixed, known shape in Node and
already depend on it, it's a proven choice. For everything else - unpredictable
shapes, browsers/CSP, value and instance coverage - this library is the safer and
more capable default, and it matches or beats the speed when you need it.

---

## Installation

```bash
pnpm add @edium/deep-redact
# or
npm install @edium/deep-redact
# or
yarn add @edium/deep-redact
```

---

## Quick start

### TypeScript / ESM

```ts
import { redact } from '@edium/deep-redact';

redact({
  user: 'ada',
  password: 'hunter2',
  session: { apiKey: 'sk_live_123', keep: 'me' }
});
// {
//   user: 'ada',
//   password: '[redacted]',
//   session: { apiKey: '[redacted]', keep: 'me' }
// }
```

### JavaScript / CommonJS

```js
const { redact } = require('@edium/deep-redact');

redact({ authorization: 'Bearer abc', ok: true });
// { authorization: '[redacted]', ok: true }
```

---

## Recipes

Pick the approach that fits the job - from the zero-config default to the
maximum-speed hot path.

**1. The easy way** - redact anything, immutably, with sensible defaults:

```ts
import { redact } from '@edium/deep-redact';
redact(anyPayload); // censored deep copy; finds password/token/apiKey/cookie/... anywhere
```

**2. Protect the console** - a last line of defense so secrets never print:

```ts
import { enableConsoleRedaction } from '@edium/deep-redact';
enableConsoleRedaction(); // every console.* call is redacted with the default patterns
console.log({ user: 'ada', password: 'hunter2' }); // -> { user: 'ada', password: '[redacted]' }
```

**3. Catch secrets hidden inside strings** (PII in free text):

```ts
const redactor = new Redactor({
  valuePatterns: [/\b\d{16}\b/, /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/] // card numbers, emails
});
redactor.redact({ note: 'card 4111111111111111 for a@b.com' });
// { note: 'card [redacted] for [redacted]' }
```

**4. Partial masking** - show just enough to be useful:

```ts
const redactor = new Redactor({
  patterns: ['card', 'ssn'],
  replacement: (value) => (typeof value === 'string' ? `****${value.slice(-4)}` : '[redacted]')
});
redactor.redact({ card: '4111111111111111', ssn: '123-45-6789' });
// { card: '****1111', ssn: '****6789' }
```

**5. The FAST way** - high-volume CSV / log export of a **known shape**:

```ts
// Register exact paths, mutate in place, and compile to a `new Function`.
// ~2x faster than fast-redact; auto-falls back to a CSP-safe walk if eval is blocked.
const csv = new Redactor({
  paths: ['user.ssn', 'user.card', 'rows[*].token'],
  mutate: true,
  compile: true
});
for (const row of rows) appendLine(csv.stringify(row)); // redact + JSON.stringify in one call
```

**6. Two redactors, two jobs** - they are fully independent, so mix freely:

```ts
enableConsoleRedaction(); // default: full walk, immutable, catches anything by key name
const csv = new Redactor({ paths: ['user.ssn'], mutate: true, compile: true }); // hot path: fast + destructive
```

---

## How matching works

Each pattern is a **regular-expression fragment** matched against **object key
names** (not values). By default the fragments are:

1. combined into a single alternation,
2. **anchored** so they match the whole key (`token` matches `token` but not
   `tokenCount`), and
3. matched **case-insensitively** (`PASSWORD`, `Password`, `password` all match).

The optional separator `[-_]?` in the built-in patterns is what lets `apiKey`,
`api_key`, and `API-KEY` all match a single `api[-_]?key` fragment.

> By default redaction is **key-based**: a secret sitting in a string value under
> a non-sensitive key (e.g. `note: 'my password is hunter2'`) is not detected. To
> catch those, add [value (content) redaction](#value-content-redaction) via
> `valuePatterns`.

### Default patterns

`DEFAULT_SENSITIVE_KEY_PATTERNS` covers the common secret-bearing field names:

```
password  passwd  pwd  secret  token  access[-_]?token  refresh[-_]?token
api[-_]?key  access[-_]?key[-_]?id  secret[-_]?access[-_]?key  authorization
auth[-_]?token  cookie  set[-_]?cookie  session[-_]?id  credentials?
private[-_]?key
```

---

## Customizing the match list

Create a `Redactor` when you want your own patterns or options, then add,
remove, or replace patterns at any time. All mutating methods are chainable.

```ts
import { Redactor, createRedactor } from '@edium/deep-redact';

// Start from the defaults and extend them.
const redactor = new Redactor();
redactor.add('ssn', 'dob').remove('cookie');

redactor.redact({ ssn: '123-45-6789', cookie: 'kept', keep: 1 });
// { ssn: '[redacted]', cookie: 'kept', keep: 1 }

// Or start from scratch.
const strict = createRedactor({ patterns: [], replacement: '***' });
strict.replace(['token', 'secret']);
```

### Managing patterns

| Method                | Description                                    |
| --------------------- | ---------------------------------------------- |
| `add(...patterns)`    | Add patterns to the list (duplicates ignored). |
| `remove(...patterns)` | Remove patterns (unknown ones ignored).        |
| `replace(patterns)`   | Swap the **entire** list for a new one.        |
| `clear()`             | Remove every pattern (matches nothing).        |
| `has(pattern)`        | Whether a pattern is currently in the list.    |
| `getPatterns()`       | A copy of the current patterns.                |
| `regex`               | The compiled matcher (read-only).              |

There is also a serialize convenience:

| Method                     | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `redact(value)`            | Returns a censored copy (or the mutated input in mutate mode).      |
| `stringify(value, space?)` | Redact **and** `JSON.stringify` in one call; `space` pretty-prints. |

```ts
const redactor = new Redactor();
redactor.stringify({ user: 'ada', password: 'hunter2' });
// '{"user":"ada","password":"[redacted]"}'
```

---

## Options

`new Redactor(options)` / `createRedactor(options)` accept:

| Option            | Type                   | Default                          | Description                                                                                                                                                                               |
| ----------------- | ---------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `patterns`        | `string[]`             | `DEFAULT_SENSITIVE_KEY_PATTERNS` | Regex fragments to match key names. Pass `[]` to start empty.                                                                                                                             |
| `valuePatterns`   | `(string \| RegExp)[]` | `[]`                             | Patterns matched against string **values**; matching substrings are censored in place (catches secrets in free text).                                                                     |
| `paths`           | `string[]`             | `[]`                             | Exact paths to redact (`headers.cookie`, `*.password`, `items[*].token`). When set, switches to fast **path-only mode**: visits only these paths; `patterns`/`valuePatterns` are ignored. |
| `replacement`     | `string \| Censor`     | `'[redacted]'`                   | Value written in place of a match. A function `(value, context) => unknown` enables partial masks. Ignored when `removeMatched` is `true`.                                                |
| `removeMatched`   | `boolean`              | `false`                          | Drop the matched key entirely instead of replacing its value. Affects objects and `Map`s only.                                                                                            |
| `mutate`          | `boolean`              | `false`                          | Redact **in place** and return the same object (fast, but destroys the input). Applies only in registered-`paths` mode; ignored during the full walk.                                     |
| `compile`         | `boolean`              | `false`                          | Compile paths to a `new Function` redactor (fastest). Needs `mutate`, wildcard-free `paths`, and a string `replacement` (or `removeMatched`); self-disables under strict CSP.             |
| `redactInstances` | `boolean`              | `false`                          | Descend into `Error`s and class instances (copied to plain objects; `Date`/`RegExp`/typed arrays still pass through).                                                                     |
| `maxDepth`        | `number`               | `8`                              | Max depth to descend before emitting `'[truncated]'`.                                                                                                                                     |
| `caseSensitive`   | `boolean`              | `false`                          | Match key names and value patterns case-sensitively.                                                                                                                                      |
| `matchWholeKey`   | `boolean`              | `true`                           | Anchor key patterns to the whole key. Set `false` for substring matching.                                                                                                                 |

```ts
// Substring matching: redacts anything containing "token".
const loose = new Redactor({ patterns: ['token'], matchWholeKey: false });
loose.redact({ tokenCount: 5, authToken: 'x' });
// { tokenCount: '[redacted]', authToken: '[redacted]' }
```

```ts
// removeMatched: strip the key entirely instead of showing a marker.
const strip = new Redactor({ removeMatched: true });
strip.redact({ user: 'ada', password: 'hunter2', session: { apiKey: 'sk_123' } });
// { user: 'ada', session: {} }
```

Invalid input is rejected eagerly: a non-string or empty pattern throws
`TypeError`, an un-compilable pattern throws `SyntaxError`, and a bad `maxDepth`
throws `RangeError`.

### Value (content) redaction

Key-name matching misses secrets hidden **inside** string values. `valuePatterns`
scans string values and censors any matching substring, leaving the rest intact.

```ts
const redactor = new Redactor({
  valuePatterns: [/\b\d{3}-\d{2}-\d{4}\b/, /\b\d{16}\b/] // SSN, card number
});
redactor.redact({ note: 'ssn 123-45-6789 on file' });
// { note: 'ssn [redacted] on file' }
```

### Registered paths (fast mode)

Declaring `paths` switches the redactor into a **fast, path-only mode**: instead
of walking the whole object, it visits _only_ the registered paths (cost scales
with the number of paths, not the size of the data). In this mode `patterns` and
`valuePatterns` are not applied - you've told it exactly where to look. Supports
single-level `*` wildcards and dot/bracket notation.

```ts
const redactor = new Redactor({ paths: ['req.headers.cookie', 'items[*].token'] });
redactor.redact({ req: { headers: { cookie: 'x', accept: '*/*' } }, items: [{ token: 't' }] });
// { req: { headers: { cookie: '[redacted]', accept: '*/*' } }, items: [{ token: '[redacted]' }] }
```

This is the tool for high-throughput logging of a **known shape** - it closes
most of the gap to path-based redactors while staying immutable and CSP-safe.
For the last bit of speed, add `mutate: true` to redact in place (destructive -
returns the same object, no copy). See [Performance](#performance).

```ts
// Fast: redact in place, no copy. Only when you don't need the original.
const fast = new Redactor({ paths: ['req.headers.cookie'], mutate: true });
fast.redact(record); // record is mutated and returned

// Fastest: also compile via `new Function` (beats fast-redact). Node/eval-capable
// environments only - it auto-falls back to the line above under a strict CSP.
const fastest = new Redactor({ paths: ['req.headers.cookie'], mutate: true, compile: true });
fastest.redact(record);
```

> **No `restore()` needed.** `fast-redact` mutates and hands you a `restore()` to
> undo it; deep-redact is **immutable by default**, so nothing is touched and
> there is nothing to restore. Need speed _and_ the original? Use registered
> `paths` without `mutate` (still fast, returns a copy). Use `mutate` only when
> you are done with the original - which also avoids the window where async code
> could observe a half-redacted object.

### Custom censor (partial masking)

Pass a function as `replacement` to reshape the output. It receives the original
value and a `RedactionContext` (`key`, `path`, `matchedBy`).

```ts
const redactor = new Redactor({
  patterns: ['card'],
  replacement: (value) => (typeof value === 'string' ? `****${value.slice(-4)}` : '[redacted]')
});
redactor.redact({ card: '4111111111111111' });
// { card: '****1111' }
```

### Redacting Errors and class instances

By default non-plain objects pass through untouched. Enable `redactInstances`
to descend into `Error`s (including `message`/`stack`) and class instances -
useful for logging Axios-style errors whose config carries secrets.

```ts
const redactor = new Redactor({ redactInstances: true });
const err = Object.assign(new Error('login failed'), {
  config: { headers: { authorization: 'Bearer secret' } }
});
redactor.redact(err);
// { name: 'Error', message: 'login failed', stack: '...',
//   config: { headers: { authorization: '[redacted]' } } }
```

---

## Console redaction

Route every `console.*` call through redaction so a matched key can never be
printed. Useful as a last line of defense in an app entrypoint.

```ts
import { enableConsoleRedaction, disableConsoleRedaction } from '@edium/deep-redact';

enableConsoleRedaction();

console.log({ user: 'ada', password: 'hunter2' });
// -> { user: 'ada', password: '[redacted]' }

disableConsoleRedaction(); // restore the original console
```

`enableConsoleRedaction(options?)` accepts every `Redactor` option, plus:

| Option     | Type                  | Default                      | Description                         |
| ---------- | --------------------- | ---------------------------- | ----------------------------------- |
| `redactor` | `Redactor`            | built from the other options | A pre-configured redactor to reuse. |
| `target`   | `Console`             | the global `console`         | The console object to patch.        |
| `methods`  | `ConsoleMethodName[]` | all data-bearing methods     | Which methods to patch.             |

```ts
// Reuse an app-wide redactor and only patch a subset of methods.
const redactor = new Redactor().add('ssn');
enableConsoleRedaction({ redactor, methods: ['log', 'info', 'warn', 'error'] });
```

Notes:

- It returns a **restore function**; calling it is equivalent to
  `disableConsoleRedaction()`.
- Calling `enableConsoleRedaction()` again cleanly **replaces** the previous
  patch, so a single disable always restores the original methods.
- `isConsoleRedactionEnabled()` reports the current state.
- If redaction ever fails on an argument, the **original argument is forwarded**
  so console output is never lost or broken.

---

## Behavior details

| Input kind                                                                               | Behavior                                                                                                  |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Plain object                                                                             | Copied; sensitive keys replaced (or dropped with `removeMatched`), others walked recursively.             |
| Array                                                                                    | Copied element-by-element.                                                                                |
| `Map`                                                                                    | Copied; values under sensitive **string** keys replaced (or dropped with `removeMatched`), others walked. |
| `Set`                                                                                    | Copied; items walked.                                                                                     |
| `null`-prototype object                                                                  | Treated as a plain object.                                                                                |
| String value                                                                             | Scanned for `valuePatterns`; matching substrings censored (else returned unchanged).                      |
| Primitives (`number`, `boolean`, `null`, `undefined`, `bigint`, `symbol`)                | Returned unchanged.                                                                                       |
| `Error`, class instances                                                                 | Passed through by reference, unless `redactInstances` is set (then copied to a censored plain object).    |
| `Date`, `RegExp`, functions, typed arrays, `ArrayBuffer`, `Promise`, `WeakMap`/`WeakSet` | Passed through **as-is** (by reference).                                                                  |
| Circular reference                                                                       | Replaced with `'[circular]'`.                                                                             |
| Nested deeper than `maxDepth`                                                            | Replaced with `'[truncated]'`.                                                                            |

The input object is **never mutated**. Unchanged subtrees are returned by
reference (copy-on-write), so treat the output as read-only.

---

## Performance

Modes, fastest to most flexible:

- **`compile` (codegen)** - `paths` + `mutate` + `compile`. Generates a bespoke
  redactor via `new Function` (fast-redact's own trick). The fastest mode; needs
  wildcard-free paths and a string replacement, and **self-disables under strict
  CSP** (falls back to the interpreted path). Requires `new Function` and mutates.
- **`mutate` (interpreted)** - `paths` + `mutate`. Redacts wildcard-free paths in
  place with a tight loop - no codegen, fully CSP-safe. Destructive.
- **Registered paths** - `paths` only. Visits just those paths (cost scales with
  path count, not object size), immutable copy-on-write. CSP-safe.
- **All (full walk)** - the default. Matches by key/value anywhere, so it must
  **visit every node**. A literal-key `Set` fast path and copy-on-write keep the
  constant factor low, but visiting is inherent to "find secrets anywhere."

Run the comparison yourself (fast-redact is a dev-only dependency):

```bash
pnpm bench
```

Representative results, ops/sec (higher is better; your numbers will vary). Two
fast-redact columns: destructive (no `restore`) and non-destructive (`+restore`),
so each is compared like-for-like.

| Scenario                              | fast-redact (destructive) | fast-redact (+restore) | **rr (compile)** | rr (mutate) | rr (paths) | rr (all) |
| ------------------------------------- | ------------------------- | ---------------------- | ---------------- | ----------- | ---------- | -------- |
| Small record → object                 | ~11.6M                    | ~10.8M                 | **~21.7M**       | ~7.5M       | ~2.4M      | ~1.0M    |
| Secrets at depth 7 → object           | ~13.6M                    | ~12.6M                 | **~20.6M**       | ~5.3M       | ~2.4M      | ~1.1M    |
| Large record (250 items), few secrets | ~11.3M                    | ~10.5M                 | **~24.6M**       | ~7.7M       | ~2.3M      | ~12K     |

Takeaways:

- **`compile` is ~1.5-2.2x faster than fast-redact** - even against fast-redact's
  fastest _destructive_ mode. Both use `new Function`; the difference is that
  fast-redact's generated redactor always **captures the original values** so its
  `restore()` can work later, whereas our compiled function is purely destructive
  and skips that bookkeeping. It's opt-in and needs an `eval`-capable environment
  (auto-fallback otherwise).
- **`mutate` reaches ~7.5M with no codegen at all** - the CSP-safe way to go fast,
  within ~1.5-2.5x of fast-redact.
- On the **large** payload, path modes are **hundreds of times faster** than the
  full walk, which must visit all 250 items to find secrets it wasn't given paths
  for.
- For typical log records every mode is sub-microsecond and the difference is
  irrelevant. Reach for `paths`/`mutate`/`compile` only for huge, known-shape
  payloads at extreme volume, and only where destroying the input is acceptable.

---

## Exports

```ts
import {
  redact, // one-shot redaction with the default patterns
  createRedactor, // factory for a configured Redactor
  Redactor, // the redaction engine (class)
  enableConsoleRedaction, // patch console.* to redact
  disableConsoleRedaction, // restore console.*
  isConsoleRedactionEnabled, // current console-redaction state
  DEFAULT_REDACTED, // '[redacted]'
  DEFAULT_MAX_DEPTH, // 8
  DEFAULT_SENSITIVE_KEY_PATTERNS,
  CIRCULAR_MARKER, // '[circular]'
  TRUNCATED_MARKER // '[truncated]'
} from '@edium/deep-redact';

// RedactionReason is an enum (a runtime value), so it is a value export.
import { RedactionReason } from '@edium/deep-redact';

import type {
  RedactorOptions,
  RedactionEngine,
  Censor,
  RedactionContext,
  ConsoleRedactionOptions,
  ConsoleMethodName
} from '@edium/deep-redact';
```

---

## Development

```bash
pnpm install
pnpm test          # vitest run with coverage
pnpm test:watch    # vitest in watch mode
pnpm lint          # eslint
pnpm type-check    # tsc --noEmit
pnpm build         # tsup -> dist (ESM + CJS + d.ts)
pnpm fix           # eslint --fix + prettier --write
```

The test suite covers traversal, every option, list mutation, input
validation, cycles/depth, and console patching at 100% coverage.

---

## License

[MIT](./LICENSE-MIT) © David LaTour
