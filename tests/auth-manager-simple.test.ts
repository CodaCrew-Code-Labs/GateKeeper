import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CognitoAuthManager } from '../src/auth-manager.js';
import { CognitoConfig } from '../src/types.js';

vi.mock('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: vi.fn().mockImplementation(() => ({
    send: vi.fn(),
  })),
  SignUpCommand: vi.fn(),
  ConfirmSignUpCommand: vi.fn(),
  InitiateAuthCommand: vi.fn(),
  AuthFlowType: {
    USER_PASSWORD_AUTH: 'USER_PASSWORD_AUTH',
  },
}));

describe('CognitoAuthManager Simple Tests', () => {
  let mockClient: unknown;
  let validConfig: CognitoConfig;

  beforeEach(async () => {
    vi.clearAllMocks();

    const { CognitoIdentityProviderClient } =
      await import('@aws-sdk/client-cognito-identity-provider');
    mockClient = {
      send: vi.fn(),
    };
    (CognitoIdentityProviderClient as unknown).mockImplementation(() => mockClient);

    validConfig = {
      userPoolId: 'us-east-1_abcdef123',
      clientId: 'abcdef123456789',
      clientSecret: 'secret123',
      region: 'us-east-1',
    };
  });

  it('should return userSub for valid signup', async () => {
    mockClient.send.mockResolvedValueOnce({
      UserSub: 'test-user-sub',
    });

    const authManager = new CognitoAuthManager(validConfig);
    const result = await authManager.signup('test@example.com', 'password123');

    expect(result).toHaveProperty('userSub');
    expect(result.userSub).toBe('test-user-sub');
  });

  it('should return tokens for valid login', async () => {
    mockClient.send.mockResolvedValueOnce({
      AuthenticationResult: {
        IdToken: 'id-token',
        AccessToken: 'access-token',
        RefreshToken: 'refresh-token',
      },
    });

    const authManager = new CognitoAuthManager(validConfig);
    const result = await authManager.login('test@example.com', 'password123');

    expect(result.idToken).toBe('id-token');
    expect(result.accessToken).toBe('access-token');
    expect(result.refreshToken).toBe('refresh-token');
  });
});
