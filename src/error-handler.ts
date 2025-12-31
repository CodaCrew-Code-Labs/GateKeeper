// Production-safe error handling utilities
// Requirements: 6.2, 6.3, 6.4

import { CognitoAuthError, ErrorCodes } from './errors.js';

/**
 * Logger interface for error handling
 */
export interface Logger {
  error(message: string, meta?: unknown): void;
  warn(message: string, meta?: unknown): void;
  info(message: string, meta?: unknown): void;
  debug(message: string, meta?: unknown): void;
}

/**
 * Default console logger implementation
 */
export class ConsoleLogger implements Logger {
  error(message: string, meta?: unknown): void {
    console.error(`[ERROR] ${message}`, meta ? JSON.stringify(meta, null, 2) : '');
  }

  warn(message: string, meta?: unknown): void {
    console.warn(`[WARN] ${message}`, meta ? JSON.stringify(meta, null, 2) : '');
  }

  info(message: string, meta?: unknown): void {
    console.info(`[INFO] ${message}`, meta ? JSON.stringify(meta, null, 2) : '');
  }

  debug(message: string, meta?: unknown): void {
    console.debug(`[DEBUG] ${message}`, meta ? JSON.stringify(meta, null, 2) : '');
  }
}

/**
 * Configuration for error handling behavior
 */
export interface ErrorHandlerConfig {
  /** Whether to include detailed error information in responses (development mode) */
  includeDetails?: boolean;
  /** Whether to log errors to the configured logger */
  enableLogging?: boolean;
  /** Logger instance to use for error logging */
  logger?: Logger;
  /** Environment mode (production, development, test) */
  environment?: 'production' | 'development' | 'test';
}

/**
 * Sanitized error response for client consumption
 */
export interface ErrorResponse {
  error: string;
  message: string;
  code?: string;
  details?: unknown;
  timestamp: string;
  requestId?: string;
}

/**
 * Internal error details for logging
 */
export interface ErrorLogEntry {
  error: string;
  message: string;
  code: string;
  statusCode: number;
  stack?: string;
  originalError?: unknown;
  context?: unknown;
  timestamp: string;
  requestId?: string;
}

/**
 * Production-safe error handler utility
 * Provides secure error responses while maintaining detailed internal logging
 * Requirements: 6.2, 6.3
 */
export class ErrorHandler {
  private config: Required<ErrorHandlerConfig>;

  constructor(config: ErrorHandlerConfig = {}) {
    this.config = {
      includeDetails: config.includeDetails ?? config.environment !== 'production',
      enableLogging: config.enableLogging ?? true,
      logger: config.logger ?? new ConsoleLogger(),
      environment: config.environment ?? 'production',
    };
  }

  /**
   * Process error and return sanitized response for clients
   * Requirements: 6.2, 6.3
   *
   * @param error Error to process
   * @param context Additional context for logging
   * @param requestId Optional request ID for tracing
   * @returns Sanitized error response
   */
  public handleError(
    error: unknown,
    context?: unknown,
    requestId?: string
  ): { response: ErrorResponse; statusCode: number } {
    const timestamp = new Date().toISOString();

    // Process the error to extract relevant information
    const processedError = this.processError(error);

    // Log detailed error information internally
    if (this.config.enableLogging) {
      this.logError(processedError, context, requestId, timestamp);
    }

    // Create sanitized response for client
    const response = this.createClientResponse(processedError, timestamp, requestId);

    return {
      response,
      statusCode: processedError.statusCode,
    };
  }

  /**
   * Process unknown error into structured format
   * @param error Unknown error object
   * @returns Processed error information
   */
  private processError(error: unknown): {
    name: string;
    message: string;
    code: string;
    statusCode: number;
    stack?: string;
    originalError: unknown;
  } {
    // Handle CognitoAuthError instances
    if (error instanceof CognitoAuthError) {
      const result: {
        name: string;
        message: string;
        code: string;
        statusCode: number;
        stack?: string;
        originalError: unknown;
      } = {
        name: error.name,
        message: error.message,
        code: error.code,
        statusCode: error.statusCode,
        originalError: error,
      };
      if (error.stack !== undefined) {
        result.stack = error.stack;
      }
      return result;
    }

    // Handle AWS SDK errors
    if (error && typeof error === 'object' && 'name' in error) {
      const awsError = error as { name: string; message?: string; $metadata?: unknown };
      return this.processAWSError(awsError);
    }

    // Handle standard JavaScript errors
    if (error instanceof Error) {
      const result: {
        name: string;
        message: string;
        code: string;
        statusCode: number;
        stack?: string;
        originalError: unknown;
      } = {
        name: error.name,
        message: error.message,
        code: ErrorCodes.INTERNAL_ERROR || 'INTERNAL_ERROR',
        statusCode: 500,
        originalError: error,
      };
      if (error.stack !== undefined) {
        result.stack = error.stack;
      }
      return result;
    }

    // Handle unknown error types
    return {
      name: 'UnknownError',
      message: 'An unexpected error occurred',
      code: ErrorCodes.INTERNAL_ERROR || 'INTERNAL_ERROR',
      statusCode: 500,
      originalError: error,
    };
  }

  /**
   * Process AWS SDK specific errors
   * Requirements: 6.4
   *
   * @param awsError AWS SDK error object
   * @returns Processed error information
   */
  private processAWSError(awsError: { name: string; message?: string; $metadata?: unknown }): {
    name: string;
    message: string;
    code: string;
    statusCode: number;
    stack?: string;
    originalError: unknown;
  } {
    const errorName = awsError.name;
    const errorMessage = awsError.message || 'AWS service error';

    // Map AWS errors to appropriate HTTP status codes and internal codes
    switch (errorName) {
      // Authentication errors (401)
      case 'NotAuthorizedException':
      case 'InvalidPasswordException':
      case 'UserNotFoundException':
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.AUTH_FAILED,
          statusCode: 401,
          originalError: awsError,
        };

      // Validation errors (400)
      case 'InvalidParameterException':
      case 'InvalidUserPoolConfigurationException':
      case 'CodeMismatchException':
      case 'ExpiredCodeException':
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.VALIDATION_ERROR,
          statusCode: 400,
          originalError: awsError,
        };

      // Rate limiting (429)
      case 'TooManyRequestsException':
      case 'TooManyFailedAttemptsException':
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.TOO_MANY_REQUESTS,
          statusCode: 429,
          originalError: awsError,
        };

      // Network/service errors (503)
      case 'ServiceUnavailableException':
      case 'InternalErrorException':
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.SERVICE_UNAVAILABLE,
          statusCode: 503,
          originalError: awsError,
        };

      // Timeout errors (504)
      case 'TimeoutException':
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.TIMEOUT,
          statusCode: 504,
          originalError: awsError,
        };

      // Default to internal server error
      default:
        return {
          name: errorName,
          message: errorMessage,
          code: ErrorCodes.NETWORK_ERROR,
          statusCode: 500,
          originalError: awsError,
        };
    }
  }

  /**
   * Log detailed error information for internal debugging
   * Requirements: 6.2
   *
   * @param processedError Processed error information
   * @param context Additional context
   * @param requestId Request ID for tracing
   * @param timestamp Error timestamp
   */
  private logError(
    processedError: {
      name: string;
      message: string;
      code: string;
      statusCode: number;
      stack?: string;
      originalError: unknown;
    },
    context?: unknown,
    requestId?: string,
    timestamp?: string
  ): void {
    const logEntry: {
      error: string;
      message: string;
      code: string;
      statusCode: number;
      stack?: string;
      originalError: unknown;
      context: unknown;
      timestamp: string;
      requestId?: string;
    } = {
      error: processedError.name,
      message: processedError.message,
      code: processedError.code,
      statusCode: processedError.statusCode,
      stack: processedError.stack,
      originalError: this.sanitizeForLogging(processedError.originalError),
      context: this.sanitizeForLogging(context),
      timestamp: timestamp || new Date().toISOString(),
    };
    if (requestId !== undefined) {
      logEntry.requestId = requestId;
    }

    // Log at appropriate level based on status code
    if (processedError.statusCode >= 500) {
      this.config.logger.error('Internal server error occurred', logEntry);
    } else if (processedError.statusCode >= 400) {
      this.config.logger.warn('Client error occurred', logEntry);
    } else {
      this.config.logger.info('Error handled', logEntry);
    }
  }

  /**
   * Create sanitized error response for client consumption
   * Requirements: 6.3
   *
   * @param processedError Processed error information
   * @param timestamp Error timestamp
   * @param requestId Request ID for tracing
   * @returns Sanitized error response
   */
  private createClientResponse(
    processedError: {
      name: string;
      message: string;
      code: string;
      statusCode: number;
    },
    timestamp: string,
    requestId?: string
  ): ErrorResponse {
    // Generic error messages for production safety
    const genericMessages: Record<number, { error: string; message: string }> = {
      400: { error: 'Bad Request', message: 'The request contains invalid parameters' },
      401: { error: 'Unauthorized', message: 'Authentication is required' },
      403: { error: 'Forbidden', message: 'Access to this resource is denied' },
      404: { error: 'Not Found', message: 'The requested resource was not found' },
      429: { error: 'Too Many Requests', message: 'Rate limit exceeded, please try again later' },
      500: { error: 'Internal Server Error', message: 'An internal error occurred' },
      503: { error: 'Service Unavailable', message: 'The service is temporarily unavailable' },
      504: { error: 'Gateway Timeout', message: 'The request timed out' },
    };

    const generic = genericMessages[processedError.statusCode] || genericMessages[500];

    const response: ErrorResponse = {
      error: generic?.error || 'Internal Server Error',
      message: generic?.message || 'An unexpected error occurred',
      timestamp,
    };
    if (requestId !== undefined) {
      response.requestId = requestId;
    }

    // Include additional details in development mode
    if (this.config.includeDetails) {
      response.code = processedError.code;
      response.details = {
        originalMessage: processedError.message,
        errorType: processedError.name,
      };
    }

    return response;
  }

  /**
   * Sanitize objects for safe logging (remove sensitive information)
   * Requirements: 6.2
   *
   * @param obj Object to sanitize
   * @returns Sanitized object
   */
  private sanitizeForLogging(obj: unknown): unknown {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    // List of sensitive keys to redact
    const sensitiveKeys = [
      'password',
      'secret',
      'token',
      'key',
      'authorization',
      'auth',
      'credential',
      'clientSecret',
      'accessToken',
      'idToken',
      'refreshToken',
      'secretHash',
    ];

    const sanitized = { ...obj };

    // Recursively sanitize object properties
    for (const [key, value] of Object.entries(sanitized)) {
      const lowerKey = key.toLowerCase();

      // Redact sensitive keys
      if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
        sanitized[key] = '[REDACTED]';
      } else if (value && typeof value === 'object') {
        // Recursively sanitize nested objects
        sanitized[key] = this.sanitizeForLogging(value);
      }
    }

    return sanitized;
  }

  /**
   * Update configuration
   * @param config New configuration options
   */
  public updateConfig(config: Partial<ErrorHandlerConfig>): void {
    this.config = {
      ...this.config,
      ...config,
      logger: config.logger ?? this.config.logger,
    };
  }

  /**
   * Get current configuration
   * @returns Current configuration
   */
  public getConfig(): Readonly<Required<ErrorHandlerConfig>> {
    return { ...this.config };
  }
}

/**
 * Default error handler instance for convenience
 */
export const defaultErrorHandler = new ErrorHandler();

/**
 * Convenience function to handle errors with default configuration
 * @param error Error to handle
 * @param context Additional context
 * @param requestId Request ID for tracing
 * @returns Sanitized error response and status code
 */
export function handleError(
  error: unknown,
  context?: unknown,
  requestId?: string
): { response: ErrorResponse; statusCode: number } {
  return defaultErrorHandler.handleError(error, context, requestId);
}

/**
 * Create error handler with custom configuration
 * @param config Error handler configuration
 * @returns Configured error handler instance
 */
export function createErrorHandler(config: ErrorHandlerConfig): ErrorHandler {
  return new ErrorHandler(config);
}
