// Unit tests for environment variable configuration loading
// Requirements: 4.3

import { describe, test, expect } from 'vitest';
import { loadConfigFromEnv, ENV_VAR_NAMES } from '../src/config.js';

describe('Environment Variable Configuration Loading', () => {
  test('should load complete configuration from environment variables', () => {
    const mockEnv = {
      [ENV_VAR_NAMES.USER_POOL_ID]: 'us-east-1_TestPool123',
      [ENV_VAR_NAMES.CLIENT_ID]: 'testclient123',
      [ENV_VAR_NAMES.CLIENT_SECRET]: 'testsecret456',
      [ENV_VAR_NAMES.REGION]: 'us-east-1',
    };

    const config = loadConfigFromEnv(mockEnv);

    expect(config.userPoolId).toBe('us-east-1_TestPool123');
    expect(config.clientId).toBe('testclient123');
    expect(config.clientSecret).toBe('testsecret456');
    expect(config.region).toBe('us-east-1');
  });

  test('should load configuration without optional clientSecret', () => {
    const mockEnv = {
      [ENV_VAR_NAMES.USER_POOL_ID]: 'us-west-2_TestPool456',
      [ENV_VAR_NAMES.CLIENT_ID]: 'publicclient789',
      [ENV_VAR_NAMES.REGION]: 'us-west-2',
    };

    const config = loadConfigFromEnv(mockEnv);

    expect(config.userPoolId).toBe('us-west-2_TestPool456');
    expect(config.clientId).toBe('publicclient789');
    expect(config.clientSecret).toBeUndefined();
    expect(config.region).toBe('us-west-2');
  });

  test('should throw error when required environment variables are missing', () => {
    const incompleteEnv = {
      [ENV_VAR_NAMES.USER_POOL_ID]: 'us-east-1_TestPool123',
      // Missing CLIENT_ID and REGION
    };

    expect(() => loadConfigFromEnv(incompleteEnv)).toThrow('Configuration validation failed');
  });

  test('should ignore extra environment variables', () => {
    const envWithExtras = {
      [ENV_VAR_NAMES.USER_POOL_ID]: 'us-east-1_TestPool123',
      [ENV_VAR_NAMES.CLIENT_ID]: 'testclient123',
      [ENV_VAR_NAMES.REGION]: 'us-east-1',
      SOME_OTHER_VAR: 'should-be-ignored',
      RANDOM_CONFIG: 'also-ignored',
    };

    const config = loadConfigFromEnv(envWithExtras);

    expect(config.userPoolId).toBe('us-east-1_TestPool123');
    expect(config.clientId).toBe('testclient123');
    expect(config.region).toBe('us-east-1');
    expect(config.clientSecret).toBeUndefined();

    // Verify no extra properties
    expect(Object.keys(config)).toEqual(['userPoolId', 'clientId', 'region']);
  });

  test('should validate environment variable values', () => {
    const invalidEnv = {
      [ENV_VAR_NAMES.USER_POOL_ID]: 'invalid-format', // Should have underscore
      [ENV_VAR_NAMES.CLIENT_ID]: 'testclient123',
      [ENV_VAR_NAMES.REGION]: 'us-east-1',
    };

    expect(() => loadConfigFromEnv(invalidEnv)).toThrow('Configuration validation failed');
  });
});
