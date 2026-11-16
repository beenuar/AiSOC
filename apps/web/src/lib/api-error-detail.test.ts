/**
 * The server's own `detail` must reach the message a toast shows (#1934).
 *
 * The API-keys 422 carried "Invalid scope(s): detection:read. Valid scopes:
 * […]" in its body, and the console threw it away: `ApiError.message` was
 * only the status line, so the analyst saw "API 422 Unprocessable Entity —
 * /api/v1/api-keys" with no hint of why. These pin the extractor that
 * `request()` now feeds the message from.
 */

import { describe, expect, it } from 'vitest';
import { apiErrorDetail } from '@/lib/api';

describe('apiErrorDetail', () => {
  it('reads a FastAPI string detail', () => {
    const body = JSON.stringify({
      detail: 'Invalid scope(s): detection:read. Valid scopes: [...]',
    });
    expect(apiErrorDetail(body)).toBe(
      'Invalid scope(s): detection:read. Valid scopes: [...]',
    );
  });

  it('joins FastAPI validation-error arrays by their msg fields', () => {
    const body = JSON.stringify({
      detail: [
        { loc: ['body', 'body'], msg: 'Field required', type: 'missing' },
        { loc: ['body', 'name'], msg: 'String too short', type: 'string_too_short' },
      ],
    });
    expect(apiErrorDetail(body)).toBe('Field required; String too short');
  });

  it('caps a runaway detail so a toast stays a toast', () => {
    const body = JSON.stringify({ detail: 'x'.repeat(1000) });
    expect(apiErrorDetail(body)?.length).toBe(300);
  });

  it('returns null for non-JSON, empty, and detail-free bodies', () => {
    expect(apiErrorDetail('')).toBeNull();
    expect(apiErrorDetail('<html>bad gateway</html>')).toBeNull();
    expect(apiErrorDetail(JSON.stringify({ error: 'other shape' }))).toBeNull();
    expect(apiErrorDetail(JSON.stringify({ detail: '   ' }))).toBeNull();
    expect(apiErrorDetail(JSON.stringify({ detail: [{ type: 'no-msg-field' }] }))).toBeNull();
  });
});
