// Main CognitoAuthManager class
// Requirements: 1.1

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoConfig, AuthTokens, SignupResponse, AuthMiddlewareOptions } from './types.js';
import { validateCognitoConfig } from './config.js';
import { computeSecretHash } from './utils.js';
import {
  CognitoAuthError,
  ConfigurationError,
  AuthenticationError,
  ValidationError,
} from './errors.js';
import {
  validateEmail,
  validatePassword,
  validateUsername,
  validateVerificationCode,
  validateJWTToken,
} from './validation.js';
import { createAuthMiddleware } from './middleware.js';
import { ErrorHandler, createErrorHandler } from './error-handler.js';
import { RetryHandler, createRetryHandler } from './retry-handler.js';
import { RequestHandler } from 'express';

/**
 * Main authentication manager class for AWS Cognito operations
 * Requirements: 1.1
 */
export class CognitoAuthManager {
  private readonly config: CognitoConfig;
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly errorHandler: ErrorHandler;
  private readonly retryHandler: RetryHandler;

  /**
   * Create a new CognitoAuthManager instance
   * Requirements: 1.1
   *
   * @param config - Cognito configuration object
   * @throws {ConfigurationError} When configuration validation fails
   */
  constructor(config: CognitoConfig) {
    try {
      // Validate configuration using existing validation function
      this.config = validateCognitoConfig(config);
    } catch (error) {
      throw new ConfigurationError(
        `CognitoAuthManager configuration validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'INVALID_CONFIG'
      );
    }

    // Initialize AWS SDK client
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: this.config.region,
    });

    // Initialize error handler with production-safe configuration
    this.errorHandler = createErrorHandler({
      environment: (process.env.NODE_ENV as 'production' | 'development' | 'test') || 'production',
      enableLogging: true,
    });

    // Initialize retry handler for network resilience
    this.retryHandler = createRetryHandler({
      maxAttempts: 3,
      baseDelay: 1000,
      maxDelay: 10000,
      requestTimeout: 30000,
    });
  }

  /**
   * Get the current configuration (read-only)
   */
  public getConfig(): Readonly<CognitoConfig> {
    return { ...this.config };
  }

  /**
   * Helper method to compute secret hash when clientSecret is provided
   * Requirements: 1.6
   */
  private computeSecretHashIfNeeded(username: string): string | undefined {
    if (this.config.clientSecret) {
      return computeSecretHash(username, this.config.clientId, this.config.clientSecret);
    }
    return undefined;
  }

  /**
   * Sign up a new user with email and password
   * Requirements: 1.2
   *
   * @param email - User's email address
   * @param password - User's password
   * @returns Promise resolving to signup response with userSub
   * @throws {ValidationError} When input validation fails
   * @throws {AuthenticationError} When Cognito signup fails
   */
  public async signup(email: string, password: string): Promise<SignupResponse> {
    // Comprehensive input validation and sanitization
    const validatedEmail = validateEmail(email);
    const validatedPassword = validatePassword(password);

    try {
      // Execute signup with retry logic for network resilience
      const result = await this.retryHandler.execute(async () => {
        // Prepare signup command
        const secretHash = this.computeSecretHashIfNeeded(validatedEmail);

        const command = new SignUpCommand({
          ClientId: this.config.clientId,
          Username: validatedEmail,
          Password: validatedPassword,
          SecretHash: secretHash,
          UserAttributes: [
            {
              Name: 'email',
              Value: validatedEmail,
            },
          ],
        });

        // Execute signup
        const response = await this.cognitoClient.send(command);

        if (!response.UserSub) {
          throw new AuthenticationError(
            'Signup failed: No user identifier returned',
            'SIGNUP_FAILED'
          );
        }

        return {
          userSub: response.UserSub,
        };
      }, 'signup operation');

      return result.result;
    } catch (error) {
      // Use error handler for production-safe error processing
      this.errorHandler.handleError(error, {
        operation: 'signup',
        email: validatedEmail, // Will be sanitized in logs
      });

      // Re-throw with appropriate error type based on the processed error
      if (error instanceof CognitoAuthError) {
        throw error;
      }

      // Handle AWS SDK errors with enhanced error mapping
      if (error && typeof error === 'object' && 'name' in error) {
        const awsError = error as { name: string; message?: string };

        switch (awsError.name) {
          case 'UsernameExistsException':
            throw new AuthenticationError('User already exists', 'USER_EXISTS');
          case 'InvalidPasswordException':
            throw new ValidationError('Password does not meet requirements', 'INVALID_PASSWORD');
          case 'InvalidParameterException':
            throw new ValidationError('Invalid parameters provided', 'INVALID_PARAMETERS');
          case 'TooManyRequestsException':
            throw new AuthenticationError(
              'Too many requests, please try again later',
              'TOO_MANY_REQUESTS'
            );
          default:
            throw new AuthenticationError('Signup failed due to service error', 'SIGNUP_FAILED');
        }
      }

      throw new AuthenticationError('Signup failed due to unexpected error', 'SIGNUP_FAILED');
    }
  }

  /**
   * Confirm user signup with verification code
   * Requirements: 1.3
   *
   * @param username - Username (typically email) used during signup
   * @param code - Verification code received by user
   * @throws {ValidationError} When input validation fails
   * @throws {AuthenticationError} When confirmation fails
   */
  public async confirmSignup(username: string, code: string): Promise<void> {
    // Comprehensive input validation and sanitization
    const validatedUsername = validateUsername(username);
    const validatedCode = validateVerificationCode(code);

    try {
      // Execute confirmation with retry logic for network resilience
      await this.retryHandler.execute(async () => {
        // Prepare confirm signup command
        const secretHash = this.computeSecretHashIfNeeded(validatedUsername);

        const command = new ConfirmSignUpCommand({
          ClientId: this.config.clientId,
          Username: validatedUsername,
          ConfirmationCode: validatedCode,
          SecretHash: secretHash,
        });

        // Execute confirmation
        await this.cognitoClient.send(command);
      }, 'confirm signup operation');
    } catch (error) {
      // Use error handler for production-safe error processing
      this.errorHandler.handleError(error, {
        operation: 'confirmSignup',
        username: validatedUsername, // Will be sanitized in logs
      });

      if (error instanceof CognitoAuthError) {
        throw error;
      }

      // Handle AWS SDK errors with enhanced error mapping
      if (error && typeof error === 'object' && 'name' in error) {
        const awsError = error as { name: string; message?: string };

        switch (awsError.name) {
          case 'CodeMismatchException':
            throw new AuthenticationError('Invalid verification code', 'INVALID_CODE');
          case 'ExpiredCodeException':
            throw new AuthenticationError('Verification code has expired', 'CODE_EXPIRED');
          case 'UserNotFoundException':
            throw new AuthenticationError('User not found', 'USER_NOT_FOUND');
          case 'NotAuthorizedException':
            throw new AuthenticationError('User is already confirmed', 'USER_ALREADY_CONFIRMED');
          case 'TooManyFailedAttemptsException':
            throw new AuthenticationError('Too many failed attempts', 'TOO_MANY_ATTEMPTS');
          case 'TooManyRequestsException':
            throw new AuthenticationError(
              'Too many requests, please try again later',
              'TOO_MANY_REQUESTS'
            );
          default:
            throw new AuthenticationError(
              'Confirmation failed due to service error',
              'CONFIRMATION_FAILED'
            );
        }
      }

      throw new AuthenticationError(
        'Confirmation failed due to unexpected error',
        'CONFIRMATION_FAILED'
      );
    }
  }

  /**
   * Authenticate user with email and password
   * Requirements: 1.4
   *
   * @param email - User's email address
   * @param password - User's password
   * @returns Promise resolving to authentication tokens
   * @throws {ValidationError} When input validation fails
   * @throws {AuthenticationError} When login fails
   */
  public async login(email: string, password: string): Promise<AuthTokens> {
    // Comprehensive input validation and sanitization
    const validatedEmail = validateEmail(email);
    const validatedPassword = validatePassword(password);

    try {
      // Execute login with retry logic for network resilience
      const result = await this.retryHandler.execute(async () => {
        // Prepare login command
        const secretHash = this.computeSecretHashIfNeeded(validatedEmail);

        const command = new InitiateAuthCommand({
          ClientId: this.config.clientId,
          AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
          AuthParameters: {
            USERNAME: validatedEmail,
            PASSWORD: validatedPassword,
            ...(secretHash && { SECRET_HASH: secretHash }),
          },
        });

        // Execute login
        const response = await this.cognitoClient.send(command);

        if (!response.AuthenticationResult) {
          throw new AuthenticationError(
            'Login failed: No authentication result returned',
            'LOGIN_FAILED'
          );
        }

        const { IdToken, AccessToken, RefreshToken } = response.AuthenticationResult;

        if (!IdToken || !AccessToken || !RefreshToken) {
          throw new AuthenticationError(
            'Login failed: Incomplete token set returned',
            'INCOMPLETE_TOKENS'
          );
        }

        return {
          idToken: IdToken,
          accessToken: AccessToken,
          refreshToken: RefreshToken,
        };
      }, 'login operation');

      return result.result;
    } catch (error) {
      // Use error handler for production-safe error processing
      this.errorHandler.handleError(error, {
        operation: 'login',
        email: validatedEmail, // Will be sanitized in logs
      });

      if (error instanceof CognitoAuthError) {
        throw error;
      }

      // Handle AWS SDK errors with enhanced error mapping
      if (error && typeof error === 'object' && 'name' in error) {
        const awsError = error as { name: string; message?: string };

        switch (awsError.name) {
          case 'NotAuthorizedException':
            throw new AuthenticationError('Invalid email or password', 'INVALID_CREDENTIALS');
          case 'UserNotConfirmedException':
            throw new AuthenticationError('User account is not confirmed', 'USER_NOT_CONFIRMED');
          case 'UserNotFoundException':
            throw new AuthenticationError('User not found', 'USER_NOT_FOUND');
          case 'PasswordResetRequiredException':
            throw new AuthenticationError('Password reset is required', 'PASSWORD_RESET_REQUIRED');
          case 'TooManyRequestsException':
            throw new AuthenticationError(
              'Too many requests, please try again later',
              'TOO_MANY_REQUESTS'
            );
          case 'InvalidParameterException':
            throw new ValidationError('Invalid parameters provided', 'INVALID_PARAMETERS');
          default:
            throw new AuthenticationError('Login failed due to service error', 'LOGIN_FAILED');
        }
      }

      throw new AuthenticationError('Login failed due to unexpected error', 'LOGIN_FAILED');
    }
  }

  /**
   * Refresh authentication tokens using refresh token
   * Requirements: 1.5
   *
   * @param refreshToken - Valid refresh token from previous authentication
   * @returns Promise resolving to new authentication tokens
   * @throws {ValidationError} When input validation fails
   * @throws {AuthenticationError} When token refresh fails
   */
  public async refreshToken(refreshToken: string): Promise<AuthTokens> {
    // Comprehensive input validation and sanitization
    const validatedRefreshToken = validateJWTToken(refreshToken);

    try {
      // Execute token refresh with retry logic for network resilience
      const result = await this.retryHandler.execute(async () => {
        // Prepare refresh token command using InitiateAuthCommand with REFRESH_TOKEN_AUTH flow
        const command = new InitiateAuthCommand({
          ClientId: this.config.clientId,
          AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
          AuthParameters: {
            REFRESH_TOKEN: validatedRefreshToken,
            ...(this.config.clientSecret && { SECRET_HASH: this.config.clientSecret }),
          },
        });

        // Execute token refresh
        const response = await this.cognitoClient.send(command);

        if (!response.AuthenticationResult) {
          throw new AuthenticationError(
            'Token refresh failed: No authentication result returned',
            'REFRESH_FAILED'
          );
        }

        const {
          IdToken,
          AccessToken,
          RefreshToken: NewRefreshToken,
        } = response.AuthenticationResult;

        if (!IdToken || !AccessToken) {
          throw new AuthenticationError(
            'Token refresh failed: Incomplete token set returned',
            'INCOMPLETE_TOKENS'
          );
        }

        return {
          idToken: IdToken,
          accessToken: AccessToken,
          refreshToken: NewRefreshToken || validatedRefreshToken, // Use new refresh token if provided, otherwise keep the old one
        };
      }, 'refresh token operation');

      return result.result;
    } catch (error) {
      // Use error handler for production-safe error processing
      this.errorHandler.handleError(error, {
        operation: 'refreshToken',
        // Don't log the actual token for security
      });

      if (error instanceof CognitoAuthError) {
        throw error;
      }

      // Handle AWS SDK errors with enhanced error mapping
      if (error && typeof error === 'object' && 'name' in error) {
        const awsError = error as { name: string; message?: string };

        switch (awsError.name) {
          case 'NotAuthorizedException':
            throw new AuthenticationError(
              'Invalid or expired refresh token',
              'INVALID_REFRESH_TOKEN'
            );
          case 'UserNotFoundException':
            throw new AuthenticationError('User not found', 'USER_NOT_FOUND');
          case 'TooManyRequestsException':
            throw new AuthenticationError(
              'Too many requests, please try again later',
              'TOO_MANY_REQUESTS'
            );
          case 'InvalidParameterException':
            throw new ValidationError('Invalid parameters provided', 'INVALID_PARAMETERS');
          default:
            throw new AuthenticationError(
              'Token refresh failed due to service error',
              'REFRESH_FAILED'
            );
        }
      }

      throw new AuthenticationError(
        'Token refresh failed due to unexpected error',
        'REFRESH_FAILED'
      );
    }
  }

  /**
   * Create Express middleware for JWT authentication
   * Requirements: 2.1, 2.2
   *
   * @param options - Middleware configuration options
   * @returns Express middleware function that verifies JWT tokens
   */
  public authMiddleware(options: AuthMiddlewareOptions): RequestHandler {
    // Use the existing createAuthMiddleware function with this manager's configuration
    // This ensures consistent configuration between manager and middleware
    return createAuthMiddleware(this.config, options);
  }
}
