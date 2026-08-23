// secure-code-ui/src/shared/lib/redact.ts
//
// Client-side redaction helper (V16.2.5).
// Recursively walks an object and replaces values whose key matches a
// sensitive-field pattern, or whose string value looks like a high-entropy
// credential, with the literal '[REDACTED]'.
//
// This is a UI-layer defence-in-depth measure; the backend is expected to
// perform its own redaction before returning data. Having both layers means
// that a backend slip does not directly expose credentials in the operator's
// browser.

const SENSITIVE_KEY_RE =
  /api[_-]?key|password|secret|token|authorization|bearer/i;

// Matches hex or base64url strings of 24+ chars (likely high-entropy creds).
const HIGH_ENTROPY_RE = /^[A-Za-z0-9+/=_-]{24,}$/;

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_RE.test(key);
}

function isHighEntropyString(value: string): boolean {
  return HIGH_ENTROPY_RE.test(value);
}

/**
 * Recursively redact sensitive values in an arbitrary object.
 *
 * - Object keys matching SENSITIVE_KEY_RE → value replaced with '[REDACTED]'
 * - String values that look like high-entropy credentials (length ≥ 24,
 *   hex/base64 alphabet) → replaced with '[REDACTED]'
 * - Arrays, plain objects, and primitives are handled recursively / as-is.
 */
export function redactSensitive(value: unknown, parentKey?: string): unknown {
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item));
  }

  if (typeof value === "object") {
    // Object.fromEntries creates own data properties even for a hostile
    // `__proto__` key; assigning untrusted keys into `{}` would invoke its
    // legacy prototype setter.
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        isSensitiveKey(key) ? "[REDACTED]" : redactSensitive(item, key),
      ]),
    );
  }

  if (typeof value === "string") {
    // Redact if the parent key is sensitive (already handled above for objects)
    // or if the string itself looks like a high-entropy credential.
    if ((parentKey && isSensitiveKey(parentKey)) || isHighEntropyString(value)) {
      return "[REDACTED]";
    }
  }

  return value;
}
