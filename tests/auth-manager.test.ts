// Tests for auth-manager.ts
// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, OAuth Support

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CognitoAuthManager } from '../src/auth-manager.js';
import { CognitoConfig } from '../src/types.js';
import { ConfigurationError, AuthenticationError, ValidationError } from '../src/errors.js';

// Mock AWS SDK
vi.mock('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: class {
    send = vi.fn();
  },
  SignUpCommand: vi.fn(),
  ConfirmSignUpCommand: vi.fn(),
  InitiateAuthCommand: vi.fn(),
  AuthFlowType: {
    USER_PASSWORD_AUTH: 'USER_PASSWORD_AUTH',
    REFRESH_TOKEN_AUTH: 'REFRESH_TOKEN_AUTH',
  },
}));

describe('CognitoAuthManager', () => {
  let validConfig: CognitoConfig;
  let authManager: CognitoAuthManager;

  beforeEach(() => {
    vi.clearAllMocks();

    validConfig = {
      userPoolId: 'us-east-1_abcdef123',
      clientId: 'abcdef123456789',
      clientSecret: 'secret123',
      region: 'us-east-1',
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create instance with valid config', () => {
      authManager = new CognitoAuthManager(validConfig);
      expect(authManager).toBeDefined();
    });

    it('should throw ConfigurationError for invalid config', () => {
      expect(() => {
        new CognitoAuthManager({
          userPoolId: 'invalid',
          clientId: '',
          region: 'us-east-1',
        });
      }).toThrow(ConfigurationError);
    });

    it('should create instance without clientSecret', () => {
      const configWithoutSecret = {
        userPoolId: 'us-east-1_abcdef123',
        clientId: 'abcdef123456789',
        region: 'us-east-1',
      };
      authManager = new CognitoAuthManager(configWithoutSecret);
      expect(authManager).toBeDefined();
    });
  });

  describe('getConfig', () => {
    it('should return read-only configuration', () => {
      authManager = new CognitoAuthManager(validConfig);
      const config = authManager.getConfig();

      expect(config.userPoolId).toBe(validConfig.userPoolId);
      expect(config.clientId).toBe(validConfig.clientId);
      expect(config.region).toBe(validConfig.region);
    });
  });

  describe('signup', () => {
    it('should return userSub for successful signup', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        UserSub: 'test-user-sub',
      });

      const result = await authManager.signup('test@example.com', 'Password123!');

      expect(result.userSub).toBe('test-user-sub');
    });

    it('should throw error when no UserSub returned', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({});

      // Error is wrapped in NetworkError due to retry handler
      await expect(authManager.signup('test@example.com', 'Password123!')).rejects.toThrow(
        /Signup failed|identifier returned/
      );
    });

    it('should throw ValidationError for invalid email', async () => {
      authManager = new CognitoAuthManager(validConfig);

      await expect(authManager.signup('invalid-email', 'Password123!')).rejects.toThrow(
        ValidationError
      );
    });

    it('should throw ValidationError for weak password', async () => {
      authManager = new CognitoAuthManager(validConfig);

      await expect(authManager.signup('test@example.com', 'weak')).rejects.toThrow(ValidationError);
    });

    it('should handle UsernameExistsException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      // Create an Error object to properly trigger error handling
      const awsError = Object.assign(new Error('User already exists'), {
        name: 'UsernameExistsException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.signup('test@example.com', 'Password123!')).rejects.toThrow(
        /User already exists/
      );
    });

    it('should handle InvalidPasswordException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      // Create an Error object to properly trigger error handling
      const awsError = Object.assign(new Error('Password does not meet requirements'), {
        name: 'InvalidPasswordException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      // Error gets wrapped but should mention password
      await expect(authManager.signup('test@example.com', 'Password123!')).rejects.toThrow();
    });

    it('should handle TooManyRequestsException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      // For rate limiting, this should be retried but ultimately fail
      const awsError = Object.assign(new Error('Rate limit exceeded'), {
        name: 'TooManyRequestsException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValue(awsError);

      // TooManyRequestsException is retryable, so error is eventually thrown
      await expect(authManager.signup('test@example.com', 'Password123!')).rejects.toThrow();
    });
  });

  describe('signupWithUsername', () => {
    it('should create user with specific username', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        UserSub: 'test-user-sub',
      });

      const result = await authManager.signupWithUsername(
        'testuser',
        'test@example.com',
        'Password123!'
      );

      expect(result.userSub).toBe('test-user-sub');
    });

    it('should throw ValidationError for invalid username', async () => {
      authManager = new CognitoAuthManager(validConfig);

      await expect(
        authManager.signupWithUsername('', 'test@example.com', 'Password123!')
      ).rejects.toThrow(ValidationError);
    });

    it('should handle AWS errors in signupWithUsername', async () => {
      authManager = new CognitoAuthManager(validConfig);

      // Create a proper Error object
      const awsError = Object.assign(new Error('Username already exists'), {
        name: 'UsernameExistsException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(
        authManager.signupWithUsername('existinguser', 'test@example.com', 'Password123!')
      ).rejects.toThrow(/Username already exists|User already exists/);
    });
  });

  describe('confirmSignup', () => {
    it('should confirm signup successfully', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({});

      await expect(authManager.confirmSignup('testuser', '123456')).resolves.toBeUndefined();
    });

    it('should throw error for invalid code', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('Invalid verification code'), {
        name: 'CodeMismatchException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.confirmSignup('testuser', '123456')).rejects.toThrow(
        /Invalid|code/i
      );
    });

    it('should throw error for expired code', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('Code has expired'), {
        name: 'ExpiredCodeException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.confirmSignup('testuser', '123456')).rejects.toThrow(
        /expired|code/i
      );
    });

    it('should throw error for user not found', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('User not found'), {
        name: 'UserNotFoundException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.confirmSignup('unknownuser', '123456')).rejects.toThrow(
        /User not found/
      );
    });

    it('should throw error for already confirmed user', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('User is already confirmed'), {
        name: 'NotAuthorizedException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.confirmSignup('confirmeduser', '123456')).rejects.toThrow(
        /already confirmed|confirmed/i
      );
    });
  });

  describe('login', () => {
    it('should return tokens for successful login', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        AuthenticationResult: {
          IdToken: 'id-token',
          AccessToken: 'access-token',
          RefreshToken: 'refresh-token',
        },
      });

      const result = await authManager.login('test@example.com', 'Password123!');

      expect(result.idToken).toBe('id-token');
      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBe('refresh-token');
    });

    it('should throw error when no AuthenticationResult', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({});

      await expect(authManager.login('test@example.com', 'Password123!')).rejects.toThrow(
        /Login failed|authentication result/i
      );
    });

    it('should throw error for incomplete tokens', async () => {
      authManager = new CognitoAuthManager(validConfig);

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        AuthenticationResult: {
          IdToken: 'id-token',
          // Missing AccessToken and RefreshToken
        },
      });

      await expect(authManager.login('test@example.com', 'Password123!')).rejects.toThrow(
        /Login failed|Incomplete|token/i
      );
    });

    it('should handle NotAuthorizedException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('Invalid credentials'), {
        name: 'NotAuthorizedException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.login('test@example.com', 'WrongPassword!')).rejects.toThrow(
        /Invalid|credentials|password/i
      );
    });

    it('should handle UserNotConfirmedException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('User is not confirmed'), {
        name: 'UserNotConfirmedException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.login('test@example.com', 'Password123!')).rejects.toThrow(
        /not confirmed|confirmed/i
      );
    });

    it('should handle PasswordResetRequiredException', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const awsError = Object.assign(new Error('Password reset required'), {
        name: 'PasswordResetRequiredException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.login('test@example.com', 'Password123!')).rejects.toThrow(
        /Password reset|reset required/i
      );
    });
  });

  describe('refreshToken', () => {
    it('should return new tokens for valid refresh token', async () => {
      authManager = new CognitoAuthManager(validConfig);

      // Valid JWT-like token
      const refreshToken =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        AuthenticationResult: {
          IdToken: 'new-id-token',
          AccessToken: 'new-access-token',
          RefreshToken: 'new-refresh-token',
        },
      });

      const result = await authManager.refreshToken(refreshToken);

      expect(result.idToken).toBe('new-id-token');
      expect(result.accessToken).toBe('new-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
    });

    it('should use old refresh token if new one not returned', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const refreshToken =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

      vi.spyOn(authManager['cognitoClient'], 'send').mockResolvedValueOnce({
        AuthenticationResult: {
          IdToken: 'new-id-token',
          AccessToken: 'new-access-token',
          // No new RefreshToken
        },
      });

      const result = await authManager.refreshToken(refreshToken);

      expect(result.refreshToken).toBe(refreshToken);
    });

    it('should throw error for expired refresh token', async () => {
      authManager = new CognitoAuthManager(validConfig);

      const refreshToken =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

      const awsError = Object.assign(new Error('Invalid refresh token'), {
        name: 'NotAuthorizedException',
      });
      vi.spyOn(authManager['cognitoClient'], 'send').mockRejectedValueOnce(awsError);

      await expect(authManager.refreshToken(refreshToken)).rejects.toThrow(/Invalid|refresh/i);
    });

    it('should throw ValidationError for invalid token format', async () => {
      authManager = new CognitoAuthManager(validConfig);

      await expect(authManager.refreshToken('invalid-token')).rejects.toThrow(ValidationError);
    });
  });

  describe('getGoogleAuthUrl', () => {
    it('should return correct OAuth URL', () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);
      const url = authManager.getGoogleAuthUrl();

      expect(url).toContain('oauth2/authorize');
      expect(url).toContain('response_type=code');
      expect(url).toContain('identity_provider=Google');
      expect(url).toContain('client_id=' + validConfig.clientId);
      expect(url).toContain('redirect_uri');
    });

    it('should trim trailing slash from domain', () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com/',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);
      const url = authManager.getGoogleAuthUrl();

      expect(url).not.toContain('//oauth2');
    });

    it('should throw ConfigurationError when domain missing', () => {
      authManager = new CognitoAuthManager(validConfig);

      expect(() => authManager.getGoogleAuthUrl()).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError when redirectUri missing', () => {
      const configWithDomain = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
      };

      authManager = new CognitoAuthManager(configWithDomain);

      expect(() => authManager.getGoogleAuthUrl()).toThrow(ConfigurationError);
    });
  });

  describe('exchangeCodeForTokens', () => {
    let mockFetch: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      mockFetch = vi.fn();
      global.fetch = mockFetch;
    });

    it('should exchange code for tokens successfully', async () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id_token: 'id-token',
            access_token: 'access-token',
            refresh_token: 'refresh-token',
          }),
      });

      const result = await authManager.exchangeCodeForTokens('auth-code-123');

      expect(result.idToken).toBe('id-token');
      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBe('refresh-token');
    });

    it('should throw ConfigurationError when domain missing', async () => {
      authManager = new CognitoAuthManager(validConfig);

      await expect(authManager.exchangeCodeForTokens('auth-code')).rejects.toThrow(
        ConfigurationError
      );
    });

    it('should throw AuthenticationError on failed exchange', async () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: () => Promise.resolve('Invalid code'),
      });

      await expect(authManager.exchangeCodeForTokens('invalid-code')).rejects.toThrow(
        AuthenticationError
      );
    });

    it('should throw AuthenticationError for incomplete tokens', async () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id_token: 'id-token',
            // Missing access_token and refresh_token
          }),
      });

      await expect(authManager.exchangeCodeForTokens('auth-code')).rejects.toThrow(
        AuthenticationError
      );
    });

    it('should include Basic auth header when clientSecret is present', async () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id_token: 'id-token',
            access_token: 'access-token',
            refresh_token: 'refresh-token',
          }),
      });

      await authManager.exchangeCodeForTokens('auth-code');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: expect.stringMatching(/^Basic /),
          }),
        })
      );
    });

    it('should handle network errors', async () => {
      const oauthConfig = {
        ...validConfig,
        domain: 'https://myapp.auth.us-east-1.amazoncognito.com',
        redirectUri: 'https://myapp.com/callback',
      };

      authManager = new CognitoAuthManager(oauthConfig);

      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(authManager.exchangeCodeForTokens('auth-code')).rejects.toThrow(
        AuthenticationError
      );
    });
  });

  describe('authMiddleware', () => {
    it('should return middleware function', () => {
      authManager = new CognitoAuthManager(validConfig);

      const middleware = authManager.authMiddleware({ tokenUse: 'access' });

      expect(typeof middleware).toBe('function');
    });
  });
});
