import { DEFAULT_MAX_DEPTH, DEFAULT_REDACTED, DEFAULT_SENSITIVE_KEY_PATTERNS } from './constants';
import { Censor, RedactionEngine, RedactorOptions } from './types';
import { compileFlatPaths, compilePathPlan, PathPlan } from './paths';
import {
  compileKeyMatchers,
  compileValueRegex,
  normalizeKeyPatterns,
  validatePaths
} from './compile';
import { compilePathFunction } from './codegen';
import { WalkConfig } from './walkCore';
import { redactDeep } from './walk';
import { flatRedact, redactByPlan } from './planWalk';

/**
 * Deep-redacts secrets from arbitrary data by key name, value pattern, or path.
 * {@link redact} returns a censored copy and never mutates its input; the match
 * list is adjustable via {@link add}/{@link remove}/{@link replace}/{@link clear}.
 */
export class Redactor implements RedactionEngine {
  private readonly _patterns: Set<string>;
  private readonly _censor: Censor | null;
  private readonly _literalReplacement: string | null;
  private readonly _removeMatched: boolean;
  private readonly _mutate: boolean;
  private readonly _redactInstances: boolean;
  private readonly _maxDepth: number;
  private readonly _caseSensitive: boolean;
  private readonly _matchWholeKey: boolean;
  private readonly _valueRegex: RegExp | null;
  private readonly _pathPlan: PathPlan | null;
  private readonly _flatPaths: string[][] | null;
  private readonly _compiled: ((value: unknown) => unknown) | null;
  private readonly _trackPath: boolean;
  private _regex!: RegExp;
  private _config!: WalkConfig;

  public constructor(options: RedactorOptions = {}) {
    const replacement = options.replacement ?? DEFAULT_REDACTED;
    if (typeof replacement !== 'string' && typeof replacement !== 'function') {
      throw new TypeError('deep-redact: replacement must be a string or a function.');
    }

    const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    if (!Number.isInteger(maxDepth) || maxDepth < 0) {
      throw new RangeError(
        `deep-redact: maxDepth must be a non-negative integer (received ${String(maxDepth)}).`
      );
    }

    this._literalReplacement = typeof replacement === 'string' ? replacement : null;
    this._censor = typeof replacement === 'function' ? replacement : null;
    this._removeMatched = options.removeMatched ?? false;
    this._mutate = options.mutate ?? false;
    this._redactInstances = options.redactInstances ?? false;
    this._maxDepth = maxDepth;
    this._caseSensitive = options.caseSensitive ?? false;
    this._matchWholeKey = options.matchWholeKey ?? true;
    this._valueRegex = compileValueRegex(options.valuePatterns ?? [], this._caseSensitive);
    const paths = validatePaths(options.paths ?? []);
    this._pathPlan = compilePathPlan(paths);
    // Flat/compiled fast paths only apply to mutate mode over literal paths.
    this._flatPaths = this._pathPlan !== null && this._mutate ? compileFlatPaths(paths) : null;
    this._compiled =
      this._flatPaths !== null && (options.compile ?? false)
        ? compilePathFunction(this._flatPaths, this._literalReplacement, this._removeMatched)
        : null;
    // Path tracking only pays off when a censor function needs `context.path`.
    this._trackPath = typeof replacement === 'function';
    this._patterns = new Set(
      normalizeKeyPatterns(options.patterns ?? DEFAULT_SENSITIVE_KEY_PATTERNS)
    );
    this._rebuild();
  }

  /**
   * The compiled matcher reflecting the current pattern set. Read-only; use
   * {@link add} / {@link remove} / {@link replace} to change what it matches.
   */
  public get regex(): RegExp {
    return this._regex;
  }

  /**
   * Returns a censored copy of `value` (never mutating it). With registered
   * `paths`, only those paths are inspected; otherwise the whole value is walked.
   */
  public redact(value: unknown): unknown {
    if (this._compiled !== null) {
      return this._compiled(value);
    }
    if (this._flatPaths !== null) {
      return flatRedact(value, this._flatPaths, this._config);
    }
    if (this._pathPlan !== null) {
      return redactByPlan(value, this._pathPlan, this._config);
    }
    return redactDeep(value, this._config);
  }

  /**
   * Redact then `JSON.stringify` in one call; `space` pretty-prints like
   * `JSON.stringify`. Standard JSON semantics apply (`Map`/`Set` become `{}`).
   */
  public stringify(value: unknown, space?: string | number): string {
    return JSON.stringify(this.redact(value), undefined, space);
  }

  /**
   * Adds one or more patterns to the match list (duplicates are ignored).
   */
  public add(...patterns: string[]): this {
    for (const pattern of normalizeKeyPatterns(patterns)) {
      this._patterns.add(pattern);
    }
    return this._recompile();
  }

  /**
   * Removes one or more patterns from the match list. Unknown patterns are
   * ignored.
   */
  public remove(...patterns: string[]): this {
    for (const pattern of patterns) {
      this._patterns.delete(pattern);
    }
    return this._recompile();
  }

  /**
   * Replaces the entire match list with `patterns`.
   */
  public replace(patterns: readonly string[]): this {
    this._patterns.clear();
    for (const pattern of normalizeKeyPatterns(patterns)) {
      this._patterns.add(pattern);
    }
    return this._recompile();
  }

  /**
   * Removes every pattern, leaving a redactor that matches nothing.
   */
  public clear(): this {
    this._patterns.clear();
    return this._recompile();
  }

  /**
   * Whether `pattern` is currently in the match list (exact-string lookup).
   */
  public has(pattern: string): boolean {
    return this._patterns.has(pattern);
  }

  /**
   * A snapshot of the current patterns. Mutating the returned array has no
   * effect on the redactor.
   */
  public getPatterns(): string[] {
    return [...this._patterns];
  }

  /**
   * Rebuilds the compiled matchers and returns the instance, so mutators stay
   * chainable. Single home for the recompile step.
   */
  private _recompile(): this {
    this._rebuild();
    return this;
  }

  private _rebuild(): void {
    const matchers = compileKeyMatchers(
      [...this._patterns],
      this._caseSensitive,
      this._matchWholeKey
    );
    this._regex = matchers.full;
    this._config = {
      literalKeys: matchers.literalKeys,
      keyRegex: matchers.keyRegex,
      hasKeyRegex: matchers.hasKeyRegex,
      caseSensitive: this._caseSensitive,
      valueRegex: this._valueRegex,
      literalReplacement: this._literalReplacement,
      censor: this._censor,
      removeMatched: this._removeMatched,
      redactInstances: this._redactInstances,
      maxDepth: this._maxDepth,
      trackPath: this._trackPath,
      mutate: this._mutate
    };
  }
}
