/**
 * Username validation constants and utilities
 */

// Username must be 3-20 characters long and contain only letters, numbers, underscores, and hyphens
export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 20;

export const USERNAME_ERROR_MESSAGES = {
  REQUIRED: 'Username is required',
  INVALID_LENGTH: `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`,
  INVALID_FORMAT: 'Username can only contain letters, numbers, underscores, and hyphens',
  TAKEN: 'Username is already taken',
};

/**
 * Validate username format
 * @param username - Username to validate
 * @returns Object with isValid boolean and optional error message
 */
export function validateUsername(username: string): { isValid: boolean; error?: string } {
  if (!username || typeof username !== 'string') {
    return { isValid: false, error: USERNAME_ERROR_MESSAGES.REQUIRED };
  }

  if (username.length < USERNAME_MIN_LENGTH || username.length > USERNAME_MAX_LENGTH) {
    return { isValid: false, error: USERNAME_ERROR_MESSAGES.INVALID_LENGTH };
  }

  if (!USERNAME_REGEX.test(username)) {
    return { isValid: false, error: USERNAME_ERROR_MESSAGES.INVALID_FORMAT };
  }

  return { isValid: true };
}
