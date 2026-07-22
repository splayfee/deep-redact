import { PathPlan } from './paths';
import { RedactionReason } from './types';
import { censorValue, WalkConfig } from './walkCore';

/**
 * The outcome of visiting one child: its (possibly new) value, whether it
 * changed, and whether it should be removed entirely.
 */
interface ChildResult {
  value: unknown;
  changed: boolean;
  remove: boolean;
}

function redactChild(
  original: unknown,
  node: PathPlan,
  key: string | number,
  path: (string | number)[],
  config: WalkConfig
): ChildResult {
  const track = config.trackPath;
  if (track) {
    path.push(key);
  }
  let result: ChildResult;
  if (node.redact) {
    if (config.removeMatched) {
      result = { value: original, changed: true, remove: true };
    } else {
      const censored = censorValue(
        config,
        original,
        typeof key === 'string' ? key : null,
        RedactionReason.Path,
        path
      );
      result = { value: censored, changed: censored !== original, remove: false };
    }
  } else {
    const censored = applyPlan(original, node, path, config);
    result = { value: censored, changed: censored !== original, remove: false };
  }
  if (track) {
    path.pop();
  }
  return result;
}

function applyPlanObject(
  value: Record<string, unknown>,
  node: PathPlan,
  path: (string | number)[],
  config: WalkConfig
): unknown {
  const keys = node.wildcard !== null ? Object.keys(value) : [...node.children.keys()];
  let result = value;
  // In mutate mode we write straight to `value` (treat it as already cloned).
  let cloned = config.mutate;
  for (const key of keys) {
    const child = node.children.get(key) ?? node.wildcard;
    if (
      child === null ||
      child === undefined ||
      !Object.prototype.hasOwnProperty.call(value, key)
    ) {
      continue;
    }
    const outcome = redactChild(value[key], child, key, path, config);
    if (!outcome.changed) {
      continue;
    }
    if (!cloned) {
      result = { ...value };
      cloned = true;
    }
    if (outcome.remove) {
      delete result[key];
    } else {
      result[key] = outcome.value;
    }
  }
  return result;
}

function applyPlanArray(
  value: unknown[],
  node: PathPlan,
  path: (string | number)[],
  config: WalkConfig
): unknown {
  let result = value;
  let cloned = config.mutate;
  const visit = (index: number, child: PathPlan): void => {
    if (index < 0 || index >= value.length) {
      return;
    }
    const outcome = redactChild(value[index], child, index, path, config);
    if (!outcome.changed) {
      return;
    }
    if (!cloned) {
      result = value.slice();
      cloned = true;
    }
    result[index] = outcome.remove ? undefined : outcome.value;
  };
  if (node.wildcard !== null) {
    for (let index = 0; index < value.length; index += 1) {
      visit(index, node.wildcard);
    }
  } else {
    for (const [key, child] of node.children) {
      visit(Number(key), child);
    }
  }
  return result;
}

/**
 * Redacts `value` following only the branches in `node`, cloning ancestors of a
 * changed leaf (copy-on-write) and sharing everything untouched.
 */
function applyPlan(
  value: unknown,
  node: PathPlan,
  path: (string | number)[],
  config: WalkConfig
): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return applyPlanArray(value, node, path, config);
  }
  return applyPlanObject(value as Record<string, unknown>, node, path, config);
}

/**
 * Redacts only the registered paths in `plan`. Cost is proportional to the
 * number of paths, not the size of the object.
 */
export function redactByPlan(value: unknown, plan: PathPlan, config: WalkConfig): unknown {
  return applyPlan(value, plan, [], config);
}

/**
 * The CSP-safe fast path: redacts wildcard-free literal paths **in place** with
 * a tight loop - no trie, no recursion, no allocation. Requires mutate mode.
 */
export function flatRedact(
  value: unknown,
  flatPaths: readonly string[][],
  config: WalkConfig
): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  for (const segments of flatPaths) {
    let parent: unknown = value;
    for (let i = 0; i < segments.length - 1; i += 1) {
      if (parent === null || typeof parent !== 'object') {
        parent = null;
        break;
      }
      parent = (parent as Record<string, unknown>)[segments[i]];
    }
    if (parent === null || typeof parent !== 'object') {
      continue;
    }
    const leaf = segments[segments.length - 1];
    const target = parent as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(target, leaf)) {
      continue;
    }
    if (config.removeMatched) {
      delete target[leaf];
    } else {
      target[leaf] = censorValue(config, target[leaf], leaf, RedactionReason.Path, segments);
    }
  }
  return value;
}
