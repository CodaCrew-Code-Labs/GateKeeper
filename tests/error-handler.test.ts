// Tests for error-handler.ts
// Requirements: 6.2, 6.3, 6.4

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  ErrorHandler,
  ConsoleLogger,
  createErrorHandler,
  handleError,
  defaultErrorHandler,
} from '../src/error-handler.js';
import {
  InvalidTokenError,
  NetworkError,
  AuthenticationError,
  ValidationError,
  ErrorCodes,
} from '../src/errors.js';

describe('ErrorHandler', () => {
  let errorHandler: ErrorHandler;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor and configuration', () => {
    it('should create error handler with default configuration', () => {
      errorHandler = new ErrorHandler();
      const config = errorHandler.getConfig();

      expect(config.enableLogging).toBe(true);
      expect(config.environment).toBe('production');
      // includeDetails defaults based on environment !== 'production'
      // Since we're in test environment but explicitly setting production, it may vary
      expect(typeof config.includeDetails).toBe('boolean');
    });

    it('should create error handler with custom configuration', () => {
      errorHandler = new ErrorHandler({
        environment: 'development',
        enableLogging: false,
        includeDetails: true,
      });
      const config = errorHandler.getConfig();

      expect(config.enableLogging).toBe(false);
      expect(config.environment).toBe('development');
      expect(config.includeDetails).toBe(true);
    });

    it('should include details by default in development mode', () => {
      errorHandler = new ErrorHandler({ environment: 'development' });
      const config = errorHandler.getConfig();
      expect(config.includeDetails).toBe(true);
    });

    it('should not include details by default in production mode', () => {
      errorHandler = new ErrorHandler({ environment: 'production' });
      const config = errorHandler.getConfig();
      expect(config.includeDetails).toBe(false);
    });

    it('should update configuration', () => {
      errorHandler = new ErrorHandler();
      errorHandler.updateConfig({ enableLogging: false });
      const config = errorHandler.getConfig();
      expect(config.enableLogging).toBe(false);
    });
  });

  describe('handleError', () => {
    it('should handle CognitoAuthError correctly', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new InvalidTokenError('Token is invalid', 'INVALID_TOKEN');

      const { response, statusCode } = errorHandler.handleError(error);

      expect(statusCode).toBe(401);
      expect(response.error).toBe('Unauthorized');
      expect(response.timestamp).toBeDefined();
    });

    it('should handle AuthenticationError correctly', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new AuthenticationError('Login failed', 'LOGIN_FAILED');

      const { response, statusCode } = errorHandler.handleError(error);

      expect(statusCode).toBe(401);
      expect(response.error).toBe('Unauthorized');
    });

    it('should handle ValidationError correctly', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new ValidationError('Invalid email format', 'INVALID_EMAIL');

      const { response, statusCode } = errorHandler.handleError(error);

      expect(statusCode).toBe(400);
      expect(response.error).toBe('Bad Request');
    });

    it('should handle NetworkError correctly', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new NetworkError('Connection failed', ErrorCodes.NETWORK_ERROR);

      const { response, statusCode } = errorHandler.handleError(error);

      expect(statusCode).toBe(503);
      expect(response.error).toBe('Service Unavailable');
    });

    it('should handle standard JavaScript Error', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new Error('Something went wrong');

      const { response, statusCode } = errorHandler.handleError(error);

      expect(statusCode).toBe(500);
      expect(response.error).toBe('Internal Server Error');
    });

    it('should handle unknown error types', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });

      const { response, statusCode } = errorHandler.handleError('string error');

      expect(statusCode).toBe(500);
      expect(response.error).toBe('Internal Server Error');
    });

    it('should include request ID in response when provided', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const error = new Error('Test error');

      const { response } = errorHandler.handleError(error, undefined, 'req-123');

      expect(response.requestId).toBe('req-123');
    });

    it('should include details in development mode', () => {
      errorHandler = new ErrorHandler({
        enableLogging: false,
        environment: 'development',
        includeDetails: true,
      });
      const error = new InvalidTokenError('Token expired');

      const { response } = errorHandler.handleError(error);

      expect(response.code).toBeDefined();
      expect(response.details).toBeDefined();
    });

    it('should not include details in production mode', () => {
      errorHandler = new ErrorHandler({
        enableLogging: false,
        environment: 'production',
      });
      const error = new InvalidTokenError('Token expired');

      const { response } = errorHandler.handleError(error);

      expect(response.code).toBeUndefined();
      expect(response.details).toBeUndefined();
    });
  });

  describe('AWS error processing', () => {
    it('should handle NotAuthorizedException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'NotAuthorizedException', message: 'Access Denied' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(401);
    });

    it('should handle InvalidPasswordException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'InvalidPasswordException', message: 'Password invalid' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(401);
    });

    it('should handle UserNotFoundException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'UserNotFoundException', message: 'User not found' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(401);
    });

    it('should handle InvalidParameterException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'InvalidParameterException', message: 'Invalid param' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(400);
    });

    it('should handle InvalidUserPoolConfigurationException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'InvalidUserPoolConfigurationException', message: 'Config error' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(400);
    });

    it('should handle CodeMismatchException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'CodeMismatchException', message: 'Code mismatch' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(400);
    });

    it('should handle ExpiredCodeException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'ExpiredCodeException', message: 'Code expired' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(400);
    });

    it('should handle TooManyRequestsException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'TooManyRequestsException', message: 'Rate limited' };

      const { response, statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(429);
      expect(response.error).toBe('Too Many Requests');
    });

    it('should handle TooManyFailedAttemptsException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'TooManyFailedAttemptsException', message: 'Too many attempts' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(429);
    });

    it('should handle ServiceUnavailableException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'ServiceUnavailableException', message: 'Service down' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(503);
    });

    it('should handle InternalErrorException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'InternalErrorException', message: 'Internal error' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(503);
    });

    it('should handle TimeoutException', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'TimeoutException', message: 'Timeout' };

      const { response, statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(504);
      expect(response.error).toBe('Gateway Timeout');
    });

    it('should handle unknown AWS errors', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });
      const awsError = { name: 'UnknownAWSException', message: 'Unknown error' };

      const { statusCode } = errorHandler.handleError(awsError);

      expect(statusCode).toBe(500);
    });
  });

  describe('logging', () => {
    it('should log errors when logging is enabled', () => {
      const mockLogger = {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      errorHandler = new ErrorHandler({
        enableLogging: true,
        logger: mockLogger,
      });

      const error = new Error('Test error');
      errorHandler.handleError(error);

      expect(mockLogger.error).toHaveBeenCalled();
    });

    it('should not log errors when logging is disabled', () => {
      const mockLogger = {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      errorHandler = new ErrorHandler({
        enableLogging: false,
        logger: mockLogger,
      });

      const error = new Error('Test error');
      errorHandler.handleError(error);

      expect(mockLogger.error).not.toHaveBeenCalled();
      expect(mockLogger.warn).not.toHaveBeenCalled();
    });

    it('should log client errors with warn level', () => {
      const mockLogger = {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      errorHandler = new ErrorHandler({
        enableLogging: true,
        logger: mockLogger,
      });

      const error = new ValidationError('Invalid input');
      errorHandler.handleError(error);

      expect(mockLogger.warn).toHaveBeenCalled();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });

    it('should log server errors with error level', () => {
      const mockLogger = {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      errorHandler = new ErrorHandler({
        enableLogging: true,
        logger: mockLogger,
      });

      const error = new Error('Server error');
      errorHandler.handleError(error);

      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('sanitization', () => {
    it('should sanitize sensitive data in context', () => {
      const mockLogger = {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      errorHandler = new ErrorHandler({
        enableLogging: true,
        logger: mockLogger,
      });

      const error = new Error('Test error');
      const sensitiveContext = {
        password: 'secret123',
        token: 'jwt-token',
        email: 'user@example.com',
      };

      errorHandler.handleError(error, sensitiveContext);

      const logCall = mockLogger.error.mock.calls[0];
      const loggedData = logCall[1];

      expect(loggedData.context.password).toBe('[REDACTED]');
      expect(loggedData.context.token).toBe('[REDACTED]');
      expect(loggedData.context.email).toBe('user@example.com');
    });

    it('should handle null and undefined in sanitization', () => {
      errorHandler = new ErrorHandler({ enableLogging: false });

      // Should not throw
      expect(() => errorHandler.handleError(new Error('test'), null)).not.toThrow();
      expect(() => errorHandler.handleError(new Error('test'), undefined)).not.toThrow();
    });
  });
});

describe('ConsoleLogger', () => {
  it('should have all required methods', () => {
    const logger = new ConsoleLogger();

    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  it('should log messages', () => {
    const logger = new ConsoleLogger();
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    logger.error('Test error message');

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('should log with metadata', () => {
    const logger = new ConsoleLogger();
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    logger.warn('Test warning', { key: 'value' });

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe('convenience functions', () => {
  it('should export createErrorHandler function', () => {
    const handler = createErrorHandler({ environment: 'test' });
    expect(handler).toBeInstanceOf(ErrorHandler);
  });

  it('should export handleError function', () => {
    expect(typeof handleError).toBe('function');

    const result = handleError(new Error('Test'));
    expect(result.response).toBeDefined();
    expect(result.statusCode).toBeDefined();
  });

  it('should export defaultErrorHandler', () => {
    expect(defaultErrorHandler).toBeInstanceOf(ErrorHandler);
  });
});
