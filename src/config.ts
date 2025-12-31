// Configuration validation and utilities for the cognito-auth package
// Requirements: 4.1, 4.3, 4.4, 4.5

import { z } from 'zod';
import { CognitoConfig } from './types.js';

/**
 * Zod schema for validating CognitoConfig
 * Requirements: 4.1, 4.4, 4.5
 */
export const CognitoConfigSchema = z.object({
  userPoolId: z
    .string()
    .min(1, 'User Pool ID is required')
    .regex(/^[\w-]+_[a-zA-Z0-9]+$/, 'User Pool ID must be in format: region_poolId'),

  clientId: z
    .string()
    .min(1, 'Client ID is required')
    .regex(/^[a-z0-9]+$/, 'Client ID must contain only lowercase letters and numbers'),

  clientSecret: z.string().min(1, 'Client Secret cannot be empty when provided').optional(),

  region: z
    .string()
    .min(1, 'AWS region is required')
    .regex(/^[a-z0-9-]+$/, 'AWS region must be a valid region identifier'),
});

/**
 * Type-safe configuration validation function
 * Requirements: 4.1, 4.2, 4.4
 *
 * @param config - Configuration object to validate
 * @returns Validated and typed configuration
 * @throws {z.ZodError} When validation fails with detailed error information
 */
export function validateCognitoConfig(config: unknown): CognitoConfig {
  try {
    return CognitoConfigSchema.parse(config) as CognitoConfig;
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Transform Zod errors into more user-friendly messages
      const errorMessages = error.errors
        .map(err => {
          const path = err.path.join('.');
          return `${path}: ${err.message}`;
        })
        .join(', ');

      throw new Error(`Configuration validation failed: ${errorMessages}`);
    }
    throw error;
  }
}

/**
 * Environment variable names for configuration
 * Requirements: 4.3
 */
export const ENV_VAR_NAMES = {
  USER_POOL_ID: 'COGNITO_USER_POOL_ID',
  CLIENT_ID: 'COGNITO_CLIENT_ID',
  CLIENT_SECRET: 'COGNITO_CLIENT_SECRET',
  REGION: 'AWS_REGION',
} as const;

/**
 * Load configuration from environment variables
 * Requirements: 4.3
 *
 * @param env - Environment variables object (defaults to process.env)
 * @returns Configuration object loaded from environment
 * @throws {Error} When required environment variables are missing
 */
export function loadConfigFromEnv(
  env: Record<string, string | undefined> = process.env
): CognitoConfig {
  const config: Record<string, unknown> = {};

  // Add required fields if they exist
  if (env[ENV_VAR_NAMES.USER_POOL_ID]) {
    config.userPoolId = env[ENV_VAR_NAMES.USER_POOL_ID];
  }
  if (env[ENV_VAR_NAMES.CLIENT_ID]) {
    config.clientId = env[ENV_VAR_NAMES.CLIENT_ID];
  }
  if (env[ENV_VAR_NAMES.REGION]) {
    config.region = env[ENV_VAR_NAMES.REGION];
  }

  // Add optional clientSecret if it exists
  if (env[ENV_VAR_NAMES.CLIENT_SECRET]) {
    config.clientSecret = env[ENV_VAR_NAMES.CLIENT_SECRET];
  }

  return validateCognitoConfig(config);
}

/**
 * Merge configuration from multiple sources with precedence
 * Requirements: 4.3, 4.4
 *
 * @param sources - Configuration sources in order of precedence (later sources override earlier ones)
 * @returns Merged and validated configuration
 */
export function mergeConfigs(...sources: Array<Partial<CognitoConfig> | undefined>): CognitoConfig {
  const merged = sources.reduce((acc, source) => {
    if (source) {
      return { ...acc, ...source };
    }
    return acc;
  }, {} as Partial<CognitoConfig>);

  return validateCognitoConfig(merged);
}

/**
 * Check if a configuration object has all required fields
 * Requirements: 4.1, 4.4
 *
 * @param config - Configuration object to check
 * @returns True if configuration is complete and valid
 */
export function isValidConfig(config: unknown): config is CognitoConfig {
  try {
    validateCognitoConfig(config);
    return true;
  } catch {
    return false;
  }
}
