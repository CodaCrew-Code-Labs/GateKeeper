// Type definitions for the cognito-auth package

import { Request } from 'express';

/**
 * Configuration interface for CognitoAuthManager
 * Requirements: 4.1, 5.1, 5.3
 */
export interface CognitoConfig {
  /** AWS Cognito User Pool ID */
  userPoolId: string;
  /** AWS Cognito App Client ID */
  clientId: string;
  /** AWS Cognito App Client Secret (optional for public clients) */
  clientSecret?: string;
  /** AWS region where the User Pool is located */
  region: string;
}

/**
 * Authentication tokens returned from Cognito operations
 * Requirements: 4.1, 5.1
 */
export interface AuthTokens {
  /** JWT ID token containing user identity information */
  idToken: string;
  /** JWT access token for API authorization */
  accessToken: string;
  /** Refresh token for obtaining new tokens */
  refreshToken: string;
}

/**
 * User information extracted from verified JWT tokens
 * Requirements: 5.1, 5.3
 */
export interface UserInfo {
  /** User's unique identifier (sub claim) */
  sub: string;
  /** User's email address */
  email: string;
  /** Custom claims for multi-tenant support and additional metadata */
  customClaims: Record<string, unknown>;
}

/**
 * Configuration options for authentication middleware
 * Requirements: 4.1, 5.1
 */
export interface AuthMiddlewareOptions {
  /** Type of token to verify ('id' for identity, 'access' for API access) */
  tokenUse: 'id' | 'access';
  /** Skip token verification (for development/testing) */
  skipVerification?: boolean;
}

/**
 * JWT claims structure for Cognito tokens
 * Requirements: 5.1, 5.3
 */
export interface JWTClaims {
  /** User identifier */
  sub: string;
  /** User email */
  email: string;
  /** Token issuer (Cognito endpoint) */
  iss: string;
  /** Token audience (Client ID) */
  aud: string;
  /** Expiration timestamp */
  exp: number;
  /** Issued at timestamp */
  iat: number;
  /** Token use (id or access) */
  token_use: 'id' | 'access';
  /** Custom claims with 'custom:' prefix for multi-tenant support */
  [key: `custom:${string}`]: unknown;
}

/**
 * Extended Express Request interface with authenticated user information
 * Requirements: 5.1, 5.3
 */
export interface AuthenticatedRequest extends Request {
  user: UserInfo;
}

/**
 * Signup response from Cognito
 * Requirements: 4.1
 */
export interface SignupResponse {
  /** User's unique identifier from Cognito */
  userSub: string;
}

/**
 * JWKS (JSON Web Key Set) cache entry
 * Requirements: 5.1
 */
export interface JWKSCacheEntry {
  /** Array of JSON Web Keys */
  keys: unknown[];
  /** Cache expiry timestamp */
  expiry: number;
}
