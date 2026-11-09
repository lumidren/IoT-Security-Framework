/**
 * Only same-origin relative paths are accepted as post-sign-in destinations: no scheme, no
 * protocol-relative `//host` and no `/\host` (which browsers also treat as protocol-relative).
 */
export function safeRedirectPath(value: string | null | undefined, fallback = '/'): string {
  if (!value || !value.startsWith('/')) return fallback;
  if (value.startsWith('//') || value.startsWith('/\\')) return fallback;
  if (/[\u0000-\u001f\u007f]/.test(value)) return fallback;
  return value;
}
