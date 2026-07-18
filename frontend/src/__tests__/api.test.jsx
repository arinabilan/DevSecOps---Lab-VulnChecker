import { describe, expect, test, vi } from 'vitest';
import { buildApiUrl } from '../config/api';

describe('api.js', () => {
  test('buildApiUrl returns base URL when no path given', () => {
    const url = buildApiUrl();
    expect(url).toBe('/api');
  });

  test('buildApiUrl returns base URL when empty path given', () => {
    const url = buildApiUrl('');
    expect(url).toBe('/api');
  });

  test('buildApiUrl appends path starting with slash', () => {
    const url = buildApiUrl('/vulnerabilities');
    expect(url).toBe('/api/vulnerabilities');
  });

  test('buildApiUrl prepends slash to path without it', () => {
    const url = buildApiUrl('vulnerabilities');
    expect(url).toBe('/api/vulnerabilities');
  });
});
