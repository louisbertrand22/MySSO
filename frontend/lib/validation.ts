/**
 * Shared validation utilities for username
 */

export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 20;

export const USERNAME_ERROR_MESSAGES = {
  INVALID_LENGTH: `Le nom d’utilisateur doit contenir entre ${USERNAME_MIN_LENGTH} et ${USERNAME_MAX_LENGTH} caractères.`,
  INVALID_FORMAT: 'Utilisez uniquement des lettres, des chiffres, _ et -.',
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
