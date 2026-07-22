/**
 * Optional `new Function` codegen for the registered-paths fast path (the same
 * technique fast-redact uses). Strictly opt-in (`compile: true`) and self-
 * disables under strict CSP by returning `null` so callers fall back to the walk.
 */
const HAS_OWN = 'Object.prototype.hasOwnProperty';

/**
 * Compiles wildcard-free literal paths into a mutating redactor, or `null` when
 * codegen does not apply (censor function) or is unavailable (CSP blocks eval).
 */
export function compilePathFunction(
  flatPaths: readonly string[][],
  literalReplacement: string | null,
  removeMatched: boolean
): ((value: unknown) => unknown) | null {
  if (literalReplacement === null && !removeMatched) {
    return null;
  }
  const lines: string[] = ['"use strict";var p;'];
  for (const segments of flatPaths) {
    lines.push('p=o;');
    for (let i = 0; i < segments.length - 1; i += 1) {
      lines.push(`if(p!=null)p=p[${JSON.stringify(segments[i])}];`);
    }
    const leaf = JSON.stringify(segments[segments.length - 1]);
    const guard = `if(p!=null&&typeof p==="object"&&${HAS_OWN}.call(p,${leaf}))`;
    lines.push(
      removeMatched
        ? `${guard}delete p[${leaf}];`
        : `${guard}p[${leaf}]=${JSON.stringify(literalReplacement)};`
    );
  }
  lines.push('return o;');
  try {
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    return new Function('o', lines.join('')) as (value: unknown) => unknown;
  } catch {
    // new Function is blocked (e.g. strict CSP) - caller falls back to the walk.
    return null;
  }
}
