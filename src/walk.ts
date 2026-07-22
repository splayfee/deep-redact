import { CIRCULAR_MARKER, TRUNCATED_MARKER } from './constants';
import { RedactionReason } from './types';
import {
  censorValue,
  isMap,
  isPlainObject,
  isRedactableInstance,
  isSet,
  matchesKey,
  redactString,
  WalkConfig
} from './walkCore';

/**
 * Per-walk state threaded through the recursion. `path` is a mutable stack,
 * maintained only when {@link WalkConfig.trackPath} is set.
 */
interface WalkContext {
  config: WalkConfig;
  seen: WeakSet<object>;
  path: (string | number)[];
}

type Walker = (value: object, depth: number, ctx: WalkContext) => unknown;

function walkArray(value: object, depth: number, ctx: WalkContext): unknown {
  const array = value as unknown[];
  const track = ctx.config.trackPath;
  let result = array;
  let cloned = false;
  for (let index = 0; index < array.length; index += 1) {
    const original = array[index];
    if (track) {
      ctx.path.push(index);
    }
    const child = walk(original, depth + 1, ctx);
    if (track) {
      ctx.path.pop();
    }
    if (child !== original) {
      if (!cloned) {
        result = array.slice();
        cloned = true;
      }
      result[index] = child;
    }
  }
  return result;
}

function walkObject(value: object, depth: number, ctx: WalkContext): unknown {
  const object = value as Record<string, unknown>;
  const config = ctx.config;
  const track = config.trackPath;
  let result = object;
  let cloned = false;
  for (const key of Object.keys(object)) {
    const original = object[key];
    if (matchesKey(key, config)) {
      if (config.removeMatched) {
        if (!cloned) {
          result = { ...object };
          cloned = true;
        }
        delete result[key];
      } else {
        if (track) {
          ctx.path.push(key);
        }
        const censored = censorValue(config, original, key, RedactionReason.Key, ctx.path);
        if (track) {
          ctx.path.pop();
        }
        if (!cloned) {
          result = { ...object };
          cloned = true;
        }
        result[key] = censored;
      }
    } else {
      if (track) {
        ctx.path.push(key);
      }
      const child = walk(original, depth + 1, ctx);
      if (track) {
        ctx.path.pop();
      }
      if (child !== original) {
        if (!cloned) {
          result = { ...object };
          cloned = true;
        }
        result[key] = child;
      }
    }
  }
  return result;
}

function walkMap(value: object, depth: number, ctx: WalkContext): unknown {
  const map = value as Map<unknown, unknown>;
  const config = ctx.config;
  const track = config.trackPath;
  let result = map;
  let cloned = false;
  for (const [key, val] of map) {
    const keyed = typeof key === 'string';
    if (keyed && matchesKey(key, config)) {
      if (config.removeMatched) {
        if (!cloned) {
          result = new Map(map);
          cloned = true;
        }
        result.delete(key);
      } else {
        if (track) {
          ctx.path.push(key);
        }
        const censored = censorValue(config, val, key, RedactionReason.Key, ctx.path);
        if (track) {
          ctx.path.pop();
        }
        if (!cloned) {
          result = new Map(map);
          cloned = true;
        }
        result.set(key, censored);
      }
    } else {
      if (keyed && track) {
        ctx.path.push(key);
      }
      const child = walk(val, depth + 1, ctx);
      if (keyed && track) {
        ctx.path.pop();
      }
      if (child !== val) {
        if (!cloned) {
          result = new Map(map);
          cloned = true;
        }
        result.set(key, child);
      }
    }
  }
  return result;
}

function walkSet(value: object, depth: number, ctx: WalkContext): unknown {
  const set = value as Set<unknown>;
  const result = new Set<unknown>();
  let changed = false;
  for (const item of set) {
    const child = walk(item, depth + 1, ctx);
    changed = changed || child !== item;
    result.add(child);
  }
  return changed ? result : set;
}

/**
 * Copies an `Error` or class instance to a censored plain object. `Error`
 * essentials (`name`/`message`/`stack`) are included and value-scanned.
 */
function walkInstance(value: object, depth: number, ctx: WalkContext): Record<string, unknown> {
  const source = value as Record<string, unknown>;
  const config = ctx.config;
  const result: Record<string, unknown> = {};
  if (value instanceof Error) {
    result.name = value.name;
    result.message = redactString(value.message, config, ctx.path);
    if (typeof value.stack === 'string') {
      result.stack = redactString(value.stack, config, ctx.path);
    }
  }
  const track = config.trackPath;
  for (const key of Object.keys(source)) {
    if (track) {
      ctx.path.push(key);
    }
    if (matchesKey(key, config)) {
      if (!config.removeMatched) {
        result[key] = censorValue(config, source[key], key, RedactionReason.Key, ctx.path);
      }
    } else {
      result[key] = walk(source[key], depth + 1, ctx);
    }
    if (track) {
      ctx.path.pop();
    }
  }
  return result;
}

/**
 * Ordered container handlers. First match wins. Support a new container kind by
 * adding an entry here - the traversal below never needs to change.
 */
const CONTAINER_WALKERS: readonly { matches: (value: object) => boolean; walk: Walker }[] = [
  { matches: Array.isArray, walk: walkArray },
  { matches: isMap, walk: walkMap },
  { matches: isSet, walk: walkSet },
  { matches: isPlainObject, walk: walkObject }
];

function walk(value: unknown, depth: number, ctx: WalkContext): unknown {
  if (typeof value === 'string') {
    return redactString(value, ctx.config, ctx.path);
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (depth > ctx.config.maxDepth) {
    return TRUNCATED_MARKER;
  }

  const node = value;
  if (ctx.seen.has(node)) {
    return CIRCULAR_MARKER;
  }
  ctx.seen.add(node);
  try {
    for (const handler of CONTAINER_WALKERS) {
      if (handler.matches(node)) {
        return handler.walk(node, depth, ctx);
      }
    }
    if (ctx.config.redactInstances && isRedactableInstance(node)) {
      return walkInstance(node, depth, ctx);
    }
    return value;
  } finally {
    // Drop after processing so shared (non-cyclic) references are not mistaken
    // for cycles.
    ctx.seen.delete(node);
  }
}

/**
 * Returns a censored copy of `value`, never mutating the input. Unchanged
 * subtrees are shared by reference (copy-on-write), keeping large payloads cheap.
 */
export function redactDeep(value: unknown, config: WalkConfig): unknown {
  return walk(value, 0, { config, seen: new WeakSet<object>(), path: [] });
}
