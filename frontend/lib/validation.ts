/**
 * Shared validation utilities for username
 */

export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 20;

export const USERNAME_ERROR_MESSAGES = {
  INVALID_LENGTH: `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`,
  INVALID_FORMAT: 'Username can only contain letters, numbers, underscores, and hyphens',
};

export function validateUsername(username: string): { isValid: boolean; error?: string } {
  if (!username || username.length < USERNAME_MIN_LENGTH || username.length > USERNAME_MAX_LENGTH) {
    return { isValid: false, error: USERNAME_ERROR_MESSAGES.INVALID_LENGTH };
  }

  if (!USERNAME_REGEX.test(username)) {
    return { isValid: false, error: USERNAME_ERROR_MESSAGES.INVALID_FORMAT };
  }

  return { isValid: true };
}
