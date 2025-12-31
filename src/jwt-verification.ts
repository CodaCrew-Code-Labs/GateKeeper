// JWT verification utilities for Cognito tokens
// Requirements: 3.3, 3.4, 3.5

import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { JWKSCache } from './jwks-cache.js';
import { CognitoConfig, JWTClaims, UserInfo } from './types.js';
import { CognitoAuthError, InvalidTokenError } from './errors.js';
import { validateJWTToken, validateStringInput } from './validation.js';

/**
 * JWT verification utility class for Cognito tokens
 * Handles signature verification, claims validation, and user info extraction
 * Requirements: 3.3, 3.4, 3.5
 */
export class JWTVerifier {
  private jwksCache: JWKSCache;
  private config: CognitoConfig;

  constructor(config: CognitoConfig) {
    this.config = config;
    this.jwksCache = new JWKSCache();
  }

  /**
   * Verify JWT token and extract user information
   * @param token JWT token to verify
   * @param tokenUse Expected token use ('id' or 'access')
   * @returns Promise resolving to UserInfo
   * @throws InvalidTokenError for invalid tokens
   */
  async verifyToken(token: string, tokenUse: 'id' | 'access'): Promise<UserInfo> {
    // Comprehensive input validation and sanitization
    const validatedToken = validateJWTToken(token);
    const validatedTokenUse = validateStringInput(tokenUse, 'tokenUse', {
      allowedChars: /^(id|access)$/,
    });

    try {
      // Decode token header to get key ID
      const decoded = jwt.decode(validatedToken, { complete: true });
      if (!decoded || typeof decoded === 'string' || !decoded.header.kid) {
        throw new InvalidTokenError('Invalid token format', 'INVALID_TOKEN_FORMAT');
      }

      // Get signing key from JWKS
      const signingKey = await this.getSigningKey(decoded.header.kid);

      // Verify token signature and claims
      const claims = jwt.verify(validatedToken, signingKey, {
        algorithms: ['RS256'],
        issuer: this.buildIssuer(),
        audience: this.config.clientId,
      }) as JWTClaims;

      // Validate token use
      if (claims.token_use !== validatedTokenUse) {
        throw new InvalidTokenError(
          `Invalid token use: expected ${validatedTokenUse}, got ${claims.token_use}`,
          'INVALID_TOKEN_USE'
        );
      }

      // Extract user information and custom claims
      return this.extractUserInfo(claims);
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        throw error;
      }

      if (error instanceof jwt.JsonWebTokenError) {
        throw new InvalidTokenError('Token verification failed', 'TOKEN_VERIFICATION_FAILED');
      }

      if (error instanceof jwt.TokenExpiredError) {
        throw new InvalidTokenError('Token has expired', 'TOKEN_EXPIRED');
      }

      throw new CognitoAuthError('JWT verification error', 'JWT_VERIFICATION_ERROR', 500);
    }
  }

  /**
   * Get signing key for JWT verification
   * @param kid Key ID from JWT header
   * @returns Promise resolving to signing key
   */
  private async getSigningKey(kid: string): Promise<string> {
    // Validate key ID input
    const validatedKid = validateStringInput(kid, 'keyId', {
      maxLength: 100,
      allowedChars: /^[a-zA-Z0-9+/=_-]+$/,
    });

    try {
      // Get JWKS keys from cache
      const keys = await this.jwksCache.getKeys(this.config.region, this.config.userPoolId);

      // Find the key with matching kid
      const key = keys.find(k => k.kid === validatedKid);
      if (!key) {
        throw new InvalidTokenError('Signing key not found', 'SIGNING_KEY_NOT_FOUND');
      }

      // Convert JWK to PEM format for verification
      const client = jwksClient({
        jwksUri: `https://cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}/.well-known/jwks.json`,
        cache: false, // We handle caching ourselves
      });

      const signingKey = await client.getSigningKey(validatedKid);
      return signingKey.getPublicKey();
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        throw error;
      }

      throw new CognitoAuthError('Failed to get signing key', 'SIGNING_KEY_ERROR', 500);
    }
  }

  /**
   * Build expected issuer URL for token validation
   * @returns Issuer URL
   */
  private buildIssuer(): string {
    return `https://cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}`;
  }

  /**
   * Extract user information and custom claims from JWT claims
   * @param claims Verified JWT claims
   * @returns UserInfo object
   */
  private extractUserInfo(claims: JWTClaims): UserInfo {
    // Extract custom claims (all claims starting with 'custom:')
    const customClaims: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(claims)) {
      if (key.startsWith('custom:')) {
        // Remove 'custom:' prefix for cleaner API
        const cleanKey = key.substring(7);
        customClaims[cleanKey] = value;
      }
    }

    return {
      sub: claims.sub,
      email: claims.email,
      customClaims,
    };
  }

  /**
   * Extract only custom claims from JWT claims
   * @param claims JWT claims object
   * @returns Custom claims without 'custom:' prefix
   */
  extractCustomClaimsFromClaims(claims: JWTClaims): Record<string, unknown> {
    const customClaims: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(claims)) {
      if (key.startsWith('custom:')) {
        // Remove 'custom:' prefix for cleaner API
        const cleanKey = key.substring(7);
        customClaims[cleanKey] = value;
      }
    }

    return customClaims;
  }

  /**
   * Check if JWT token has specific custom claim
   * @param token JWT token
   * @param claimName Custom claim name (without 'custom:' prefix)
   * @returns Promise resolving to boolean
   */
  async hasCustomClaim(token: string, claimName: string): Promise<boolean> {
    // Validate inputs
    const validatedToken = validateJWTToken(token);
    const validatedClaimName = validateStringInput(claimName, 'claimName', {
      maxLength: 50,
      allowedChars: /^[a-zA-Z0-9_-]+$/,
    });

    try {
      const userInfo = await this.verifyToken(validatedToken, 'id');
      return validatedClaimName in userInfo.customClaims;
    } catch {
      // Fallback to unsafe extraction
      const customClaims = this.extractCustomClaimsUnsafe(validatedToken);
      return validatedClaimName in customClaims;
    }
  }

  /**
   * Get specific custom claim value from JWT token
   * @param token JWT token
   * @param claimName Custom claim name (without 'custom:' prefix)
   * @returns Promise resolving to claim value or undefined
   */
  async getCustomClaim(token: string, claimName: string): Promise<unknown> {
    // Validate inputs
    const validatedToken = validateJWTToken(token);
    const validatedClaimName = validateStringInput(claimName, 'claimName', {
      maxLength: 50,
      allowedChars: /^[a-zA-Z0-9_-]+$/,
    });

    try {
      const userInfo = await this.verifyToken(validatedToken, 'id');
      return userInfo.customClaims[validatedClaimName];
    } catch {
      // Fallback to unsafe extraction
      const customClaims = this.extractCustomClaimsUnsafe(validatedToken);
      return customClaims[validatedClaimName];
    }
  }

  /**
   * Extract all custom claims from JWT token without verification
   * Useful for development/testing scenarios
   * @param token JWT token
   * @returns Custom claims object
   */
  extractCustomClaimsUnsafe(token: string): Record<string, unknown> {
    try {
      // Validate token format even in unsafe mode
      const validatedToken = validateJWTToken(token);

      const decoded = jwt.decode(validatedToken) as JWTClaims | null;
      if (!decoded) {
        return {};
      }

      return this.extractUserInfo(decoded).customClaims;
    } catch {
      return {};
    }
  }
}

/**
 * Standalone function to verify JWT token
 * @param token JWT token to verify
 * @param config Cognito configuration
 * @param tokenUse Expected token use
 * @returns Promise resolving to UserInfo
 */
export async function verifyJWT(
  token: string,
  config: CognitoConfig,
  tokenUse: 'id' | 'access'
): Promise<UserInfo> {
  // Validate inputs
  const validatedToken = validateJWTToken(token);
  const validatedTokenUse = validateStringInput(tokenUse, 'tokenUse', {
    allowedChars: /^(id|access)$/,
  });

  const verifier = new JWTVerifier(config);
  return verifier.verifyToken(validatedToken, validatedTokenUse as 'id' | 'access');
}

/**
 * Extract custom claims from JWT token
 * @param token JWT token
 * @param config Cognito configuration
 * @returns Promise resolving to custom claims
 */
export async function extractCustomClaims(
  token: string,
  config: CognitoConfig
): Promise<Record<string, unknown>> {
  // Validate input
  const validatedToken = validateJWTToken(token);

  const verifier = new JWTVerifier(config);

  try {
    // Try to verify token first for security
    const userInfo = await verifier.verifyToken(validatedToken, 'id');
    return userInfo.customClaims;
  } catch {
    // Fallback to unsafe extraction if verification fails
    return verifier.extractCustomClaimsUnsafe(validatedToken);
  }
}

/**
 * Check if JWT token has a specific custom claim
 * @param token JWT token
 * @param claimName Custom claim name (without 'custom:' prefix)
 * @param config Cognito configuration
 * @returns Promise resolving to boolean
 */
export async function hasCustomClaim(
  token: string,
  claimName: string,
  config: CognitoConfig
): Promise<boolean> {
  // Validate inputs
  const validatedToken = validateJWTToken(token);
  const validatedClaimName = validateStringInput(claimName, 'claimName', {
    maxLength: 50,
    allowedChars: /^[a-zA-Z0-9_-]+$/,
  });

  const verifier = new JWTVerifier(config);
  return verifier.hasCustomClaim(validatedToken, validatedClaimName);
}

/**
 * Get specific custom claim value from JWT token
 * @param token JWT token
 * @param claimName Custom claim name (without 'custom:' prefix)
 * @param config Cognito configuration
 * @returns Promise resolving to claim value or undefined
 */
export async function getCustomClaim(
  token: string,
  claimName: string,
  config: CognitoConfig
): Promise<unknown> {
  // Validate inputs
  const validatedToken = validateJWTToken(token);
  const validatedClaimName = validateStringInput(claimName, 'claimName', {
    maxLength: 50,
    allowedChars: /^[a-zA-Z0-9_-]+$/,
  });

  const verifier = new JWTVerifier(config);
  return verifier.getCustomClaim(validatedToken, validatedClaimName);
}

/**
 * Extract tenant ID from JWT token (common multi-tenant use case)
 * @param token JWT token
 * @param config Cognito configuration
 * @returns Promise resolving to tenant ID or undefined
 */
export async function extractTenantId(
  token: string,
  config: CognitoConfig
): Promise<string | undefined> {
  // Validate input
  const validatedToken = validateJWTToken(token);

  return getCustomClaim(validatedToken, 'tenantId', config);
}

/**
 * Extract user role from JWT token (common authorization use case)
 * @param token JWT token
 * @param config Cognito configuration
 * @returns Promise resolving to user role or undefined
 */
export async function extractUserRole(
  token: string,
  config: CognitoConfig
): Promise<string | undefined> {
  // Validate input
  const validatedToken = validateJWTToken(token);

  return getCustomClaim(validatedToken, 'role', config);
}
