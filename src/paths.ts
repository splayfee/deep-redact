/**
 * A node in the compiled path plan (a trie of registered paths). The walk
 * follows only these branches, so cost scales with path count, not object size.
 */
export interface PathPlan {
  /** Literal child segments (object keys / array indices as strings). */
  children: Map<string, PathPlan>;
  /** The `*` branch, matching any single key/index at this level, or `null`. */
  wildcard: PathPlan | null;
  /** When `true`, the value reached at this node is redacted. */
  redact: boolean;
}

/** A single path segment matching any key/index. Written as `*` in a path. */
const WILDCARD = '*';

/**
 * Splits a path string into segments, accepting dot notation and bracket
 * notation for indices/keys: `a.b`, `a[0].b`, `a[*].b`, and `a["x-y"].b`.
 */
export function parsePath(path: string): string[] {
  const normalized = path.replace(/\[(\d+|\*)\]/g, '.$1').replace(/\[["']([^"']+)["']\]/g, '.$1');
  return normalized.split('.').filter((segment) => {
    return segment.length > 0;
  });
}

function emptyNode(): PathPlan {
  return { children: new Map<string, PathPlan>(), wildcard: null, redact: false };
}

/**
 * Compiles path strings into a single trie, or `null` when none are given.
 * Shared prefixes are merged, so overlapping paths cost nothing extra to walk.
 */
export function compilePathPlan(paths: readonly string[]): PathPlan | null {
  if (paths.length === 0) {
    return null;
  }
  const root = emptyNode();
  for (const path of paths) {
    let node = root;
    for (const segment of parsePath(path)) {
      if (segment === WILDCARD) {
        node.wildcard ??= emptyNode();
        node = node.wildcard;
      } else {
        let child = node.children.get(segment);
        if (child === undefined) {
          child = emptyNode();
          node.children.set(segment, child);
        }
        node = child;
      }
    }
    node.redact = true;
  }
  return root;
}

/**
 * Parses paths into flat segment lists for the fast literal-path modes, or
 * `null` when any path has a `*` wildcard (those need the trie). Empty ones drop.
 */
export function compileFlatPaths(paths: readonly string[]): string[][] | null {
  const flat: string[][] = [];
  for (const path of paths) {
    const segments = parsePath(path);
    if (segments.includes(WILDCARD)) {
      return null;
    }
    if (segments.length > 0) {
      flat.push(segments);
    }
  }
  return flat.length > 0 ? flat : null;
}
