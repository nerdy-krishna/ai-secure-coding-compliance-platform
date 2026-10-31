// secure-code-ui/src/shared/lib/passwordPolicy.ts
//
// Shared password policy for every UI surface that sets a password.
//
// This mirrors the backend rules in `src/app/infrastructure/auth/schemas.py`
// (`_MIN_PASSWORD_LEN`, `_MAX_PASSWORD_LEN`, `_check_password_complexity`).
// Keep in sync if the server-side rules change: the server is authoritative
// and re-validates, but the UI must never let a user submit a password the
// server will reject silently.

export const MIN_PASSWORD_LEN = 12;
export const MAX_PASSWORD_LEN = 128;
export const MIN_PASSWORD_CLASSES = 2;

export interface PasswordRequirement {
  label: string;
  met: boolean;
}

/** Number of distinct character classes present (lower, upper, digit, symbol). */
export function passwordClassCount(password: string): number {
  let count = 0;
  if (/[a-z]/.test(password)) count += 1;
  if (/[A-Z]/.test(password)) count += 1;
  if (/[0-9]/.test(password)) count += 1;
  if (/[^a-zA-Z0-9]/.test(password)) count += 1;
  return count;
}

/**
 * Returns a user-facing error message, or `null` when the password satisfies
 * the policy.
 */
export function validatePassword(password: string): string | null {
  if (password.length < MIN_PASSWORD_LEN) {
    return `Password must be at least ${MIN_PASSWORD_LEN} characters.`;
  }
  if (password.length > MAX_PASSWORD_LEN) {
    return `Password must be at most ${MAX_PASSWORD_LEN} characters.`;
  }
  if (passwordClassCount(password) < MIN_PASSWORD_CLASSES) {
    return "Password must mix at least two character classes (e.g. letters + digits, letters + symbols).";
  }
  return null;
}

/** Checklist rows for rendering the policy next to a password input. */
export function passwordRequirements(password: string): PasswordRequirement[] {
  return [
    {
      label: `${MIN_PASSWORD_LEN}–${MAX_PASSWORD_LEN} characters`,
      met:
        password.length >= MIN_PASSWORD_LEN &&
        password.length <= MAX_PASSWORD_LEN,
    },
    {
      label: `${MIN_PASSWORD_CLASSES}+ character types (lowercase, uppercase, digits, symbols)`,
      met: passwordClassCount(password) >= MIN_PASSWORD_CLASSES,
    },
  ];
}
