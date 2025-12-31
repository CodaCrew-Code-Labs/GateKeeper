// Custom error classes for the cognito-auth package
// Requirements: 6.1

/**
 * Base error class for all Cognito authentication errors
 * Provides consistent error structure with codes and HTTP status mapping
 */
export class CognitoAuthError extends Error {
  public readonly name: string = 'CognitoAuthError';

  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 500
  ) {
    super(message);

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, CognitoAuthError.prototype);

    // Capture stack trace if available
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, CognitoAuthError);
    }
  }

  /**
   * Convert error to JSON representation (safe for logging)
   */
  toJSON(): {
    name: string;
    message: string;
    code: string;
    statusCode: number;
    stack?: string;
  } {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      stack: this.stack,
    };
  }
}

/**
 * Error thrown when JWT token validation fails
 * HTTP Status: 401 Unauthorized
 */
export class InvalidTokenError extends CognitoAuthError {
  public readonly name: string = 'InvalidTokenError';

  constructor(message: string = 'Invalid or expired token', code: string = 'INVALID_TOKEN') {
    super(message, code, 401);
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

/**
 * Error thrown when configuration validation fails
 * HTTP Status: 500 Internal Server Error
 */
export class ConfigurationError extends CognitoAuthError {
  public readonly name: string = 'ConfigurationError';

  constructor(message: string = 'Invalid configuration', code: string = 'INVALID_CONFIG') {
    super(message, code, 500);
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * Error thrown when network communication with AWS fails
 * HTTP Status: 503 Service Unavailable
 */
export class NetworkError extends CognitoAuthError {
  public readonly name: string = 'NetworkError';

  constructor(message: string = 'Network communication failed', code: string = 'NETWORK_ERROR') {
    super(message, code, 503);
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Error thrown when input validation fails
 * HTTP Status: 400 Bad Request
 */
export class ValidationError extends CognitoAuthError {
  public readonly name: string = 'ValidationError';

  constructor(message: string = 'Input validation failed', code: string = 'VALIDATION_ERROR') {
    super(message, code, 400);
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Error thrown when authentication fails (wrong credentials)
 * HTTP Status: 401 Unauthorized
 */
export class AuthenticationError extends CognitoAuthError {
  public readonly name: string = 'AuthenticationError';

  constructor(message: string = 'Authentication failed', code: string = 'AUTH_FAILED') {
    super(message, code, 401);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Error thrown when user lacks required permissions
 * HTTP Status: 403 Forbidden
 */
export class AuthorizationError extends CognitoAuthError {
  public readonly name: string = 'AuthorizationError';

  constructor(
    message: string = 'Insufficient permissions',
    code: string = 'INSUFFICIENT_PERMISSIONS'
  ) {
    super(message, code, 403);
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

/**
 * Error code constants for consistent error handling
 */
export const ErrorCodes = {
  // Configuration errors
  INVALID_CONFIG: 'INVALID_CONFIG',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',

  // Authentication errors
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_MALFORMED: 'TOKEN_MALFORMED',
  AUTH_FAILED: 'AUTH_FAILED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',

  // Authorization errors
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  ACCESS_DENIED: 'ACCESS_DENIED',

  // Network errors
  NETWORK_ERROR: 'NETWORK_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  TIMEOUT: 'TIMEOUT',

  // Validation errors
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MALFORMED_REQUEST: 'MALFORMED_REQUEST',

  // Cognito-specific errors
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  USER_NOT_CONFIRMED: 'USER_NOT_CONFIRMED',
  INVALID_VERIFICATION_CODE: 'INVALID_VERIFICATION_CODE',
  CODE_EXPIRED: 'CODE_EXPIRED',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',

  // Internal errors
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

/**
 * HTTP status code mapping for different error types
 */
export const HttpStatusCodes = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
} as const;
