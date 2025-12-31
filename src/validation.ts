// Comprehensive input validation and sanitization utilities
// Requirements: 6.5

import { ValidationError } from './errors.js';

/**
 * Email validation with comprehensive security checks
 * Requirements: 6.5
 */
export function validateEmail(email: unknown): string {
  // Type check
  if (typeof email !== 'string') {
    throw new ValidationError('Email must be a string', 'INVALID_EMAIL_TYPE');
  }

  // Basic sanitization - trim whitespace
  const sanitizedEmail = email.trim();

  // Length checks
  if (sanitizedEmail.length === 0) {
    throw new ValidationError('Email is required', 'EMPTY_EMAIL');
  }

  if (sanitizedEmail.length > 254) {
    throw new ValidationError('Email is too long (max 254 characters)', 'EMAIL_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedEmail)) {
    throw new ValidationError('Email contains invalid characters', 'INVALID_EMAIL_CHARS');
  }

  // Comprehensive email regex validation
  const emailRegex =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  if (!emailRegex.test(sanitizedEmail)) {
    throw new ValidationError('Invalid email format', 'INVALID_EMAIL_FORMAT');
  }

  // Additional security checks
  // Check for multiple @ symbols
  if ((sanitizedEmail.match(/@/g) || []).length !== 1) {
    throw new ValidationError('Email must contain exactly one @ symbol', 'INVALID_EMAIL_FORMAT');
  }

  // Check for consecutive dots
  if (sanitizedEmail.includes('..')) {
    throw new ValidationError('Email cannot contain consecutive dots', 'INVALID_EMAIL_FORMAT');
  }

  // Check for leading/trailing dots in local part
  const [localPart] = sanitizedEmail.split('@');
  if (!localPart || localPart.startsWith('.') || localPart.endsWith('.')) {
    throw new ValidationError(
      'Email local part cannot start or end with a dot',
      'INVALID_EMAIL_FORMAT'
    );
  }

  return sanitizedEmail;
}

/**
 * Password validation with security requirements
 * Requirements: 6.5
 */
export function validatePassword(password: unknown): string {
  // Type check
  if (typeof password !== 'string') {
    throw new ValidationError('Password must be a string', 'INVALID_PASSWORD_TYPE');
  }

  // Length checks
  if (password.length === 0) {
    throw new ValidationError('Password is required', 'EMPTY_PASSWORD');
  }

  if (password.length < 8) {
    throw new ValidationError('Password must be at least 8 characters long', 'PASSWORD_TOO_SHORT');
  }

  if (password.length > 256) {
    throw new ValidationError('Password is too long (max 256 characters)', 'PASSWORD_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(password)) {
    throw new ValidationError('Password contains invalid characters', 'INVALID_PASSWORD_CHARS');
  }

  // Note: We don't enforce complexity requirements here as Cognito handles that
  // But we ensure the password is safe from injection attacks

  return password;
}

/**
 * Username validation (typically email, but can be other formats)
 * Requirements: 6.5
 */
export function validateUsername(username: unknown): string {
  // Type check
  if (typeof username !== 'string') {
    throw new ValidationError('Username must be a string', 'INVALID_USERNAME_TYPE');
  }

  // Basic sanitization
  const sanitizedUsername = username.trim();

  // Length checks
  if (sanitizedUsername.length === 0) {
    throw new ValidationError('Username is required', 'EMPTY_USERNAME');
  }

  if (sanitizedUsername.length > 128) {
    throw new ValidationError('Username is too long (max 128 characters)', 'USERNAME_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedUsername)) {
    throw new ValidationError('Username contains invalid characters', 'INVALID_USERNAME_CHARS');
  }

  // Allow alphanumeric, email format, and common username characters
  const usernameRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~@-]+$/;
  if (!usernameRegex.test(sanitizedUsername)) {
    throw new ValidationError('Username contains invalid characters', 'INVALID_USERNAME_FORMAT');
  }

  return sanitizedUsername;
}

/**
 * Verification code validation
 * Requirements: 6.5
 */
export function validateVerificationCode(code: unknown): string {
  // Type check
  if (typeof code !== 'string') {
    throw new ValidationError('Verification code must be a string', 'INVALID_CODE_TYPE');
  }

  // Basic sanitization
  const sanitizedCode = code.trim();

  // Length checks
  if (sanitizedCode.length === 0) {
    throw new ValidationError('Verification code is required', 'EMPTY_CODE');
  }

  if (sanitizedCode.length > 20) {
    throw new ValidationError('Verification code is too long', 'CODE_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedCode)) {
    throw new ValidationError(
      'Verification code contains invalid characters',
      'INVALID_CODE_CHARS'
    );
  }

  // Verification codes should only contain alphanumeric characters
  const codeRegex = /^[a-zA-Z0-9]+$/;
  if (!codeRegex.test(sanitizedCode)) {
    throw new ValidationError(
      'Verification code must contain only letters and numbers',
      'INVALID_CODE_FORMAT'
    );
  }

  return sanitizedCode;
}

/**
 * JWT token validation and sanitization
 * Requirements: 6.5
 */
export function validateJWTToken(token: unknown): string {
  // Type check
  if (typeof token !== 'string') {
    throw new ValidationError('Token must be a string', 'INVALID_TOKEN_TYPE');
  }

  // Basic sanitization
  const sanitizedToken = token.trim();

  // Length checks
  if (sanitizedToken.length === 0) {
    throw new ValidationError('Token is required', 'EMPTY_TOKEN');
  }

  // JWT tokens can be quite long, but set a reasonable upper limit
  if (sanitizedToken.length > 4096) {
    throw new ValidationError('Token is too long', 'TOKEN_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedToken)) {
    throw new ValidationError('Token contains invalid characters', 'INVALID_TOKEN_CHARS');
  }

  // JWT tokens should only contain base64url characters and dots
  const jwtRegex = /^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/;
  if (!jwtRegex.test(sanitizedToken)) {
    throw new ValidationError('Token format is invalid', 'INVALID_TOKEN_FORMAT');
  }

  return sanitizedToken;
}

/**
 * Generic string input validation with injection protection
 * Requirements: 6.5
 */
export function validateStringInput(
  input: unknown,
  fieldName: string,
  options: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    allowedChars?: RegExp;
  } = {}
): string {
  const { required = true, minLength = 0, maxLength = 1000, allowedChars } = options;

  // Type check
  if (typeof input !== 'string') {
    throw new ValidationError(`${fieldName} must be a string`, 'INVALID_INPUT_TYPE');
  }

  // Basic sanitization
  const sanitizedInput = input.trim();

  // Required check
  if (required && sanitizedInput.length === 0) {
    throw new ValidationError(`${fieldName} is required`, 'EMPTY_INPUT');
  }

  // Allow empty strings if not required
  if (!required && sanitizedInput.length === 0) {
    return sanitizedInput;
  }

  // Length checks
  if (sanitizedInput.length < minLength) {
    throw new ValidationError(
      `${fieldName} must be at least ${minLength} characters long`,
      'INPUT_TOO_SHORT'
    );
  }

  if (sanitizedInput.length > maxLength) {
    throw new ValidationError(
      `${fieldName} is too long (max ${maxLength} characters)`,
      'INPUT_TOO_LONG'
    );
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedInput)) {
    throw new ValidationError(`${fieldName} contains invalid characters`, 'INVALID_INPUT_CHARS');
  }

  // Custom character validation if provided
  if (allowedChars && !allowedChars.test(sanitizedInput)) {
    throw new ValidationError(`${fieldName} contains invalid characters`, 'INVALID_INPUT_FORMAT');
  }

  return sanitizedInput;
}

/**
 * Validate Authorization header format
 * Requirements: 6.5
 */
export function validateAuthorizationHeader(header: unknown): string | null {
  // Type check
  if (typeof header !== 'string') {
    return null;
  }

  // Basic sanitization
  const sanitizedHeader = header.trim();

  // Length checks
  if (sanitizedHeader.length === 0) {
    return null;
  }

  if (sanitizedHeader.length > 4200) {
    // Bearer + space + JWT token
    throw new ValidationError('Authorization header is too long', 'HEADER_TOO_LONG');
  }

  // Check for null bytes and control characters (injection protection)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(sanitizedHeader)) {
    throw new ValidationError(
      'Authorization header contains invalid characters',
      'INVALID_HEADER_CHARS'
    );
  }

  // Must start with 'Bearer '
  if (!sanitizedHeader.startsWith('Bearer ')) {
    return null;
  }

  // Check if there's actually a token after 'Bearer '
  const token = sanitizedHeader.substring(7).trim();
  if (token.length === 0) {
    return null;
  }

  return sanitizedHeader;
}

/**
 * Sanitize object for logging (remove sensitive data)
 * Requirements: 6.5
 */
export function sanitizeForLogging(obj: unknown): Record<string, unknown> {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    // Mask potential tokens or secrets
    if (obj.length > 20 && /^[a-zA-Z0-9._-]+$/.test(obj)) {
      return `${obj.substring(0, 8)}...${obj.substring(obj.length - 4)}`;
    }
    return obj;
  }

  if (typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeForLogging);
  }

  const sanitized: Record<string, unknown> = {};
  const sensitiveKeys = [
    'password',
    'secret',
    'token',
    'key',
    'auth',
    'credential',
    'clientSecret',
    'refreshToken',
    'accessToken',
    'idToken',
  ];

  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = sensitiveKeys.some(sensitiveKey => lowerKey.includes(sensitiveKey));

    if (isSensitive && typeof value === 'string') {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = sanitizeForLogging(value);
    }
  }

  return sanitized;
}
