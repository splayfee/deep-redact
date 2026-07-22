import { describe, expect, it } from 'vitest';
import { createRedactor, redact } from '../src/factory';
import { Redactor } from '../src/Redactor';
import { DEFAULT_REDACTED } from '../src/constants';

describe('createRedactor', () => {
  it('returns a Redactor instance', (): void => {
    expect(createRedactor()).toBeInstanceOf(Redactor);
  });

  it('forwards options to the instance', (): void => {
    const redactor = createRedactor({ patterns: ['ssn'], replacement: '##' });
    expect(redactor.redact({ ssn: '1', password: 'p' })).toEqual({ ssn: '##', password: 'p' });
  });
});

describe('redact', () => {
  it('censors sensitive keys using the default pattern set', (): void => {
    expect(redact({ password: 'p', keep: 1 })).toEqual({ password: DEFAULT_REDACTED, keep: 1 });
  });

  it('does not mutate its input', (): void => {
    const input = { token: 't' };
    redact(input);
    expect(input).toEqual({ token: 't' });
  });
});
