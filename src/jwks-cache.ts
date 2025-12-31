// JWKS (JSON Web Key Set) caching utility
// Requirements: 3.1, 3.2

import { JWKSCacheEntry } from './types.js';
import { NetworkError, ErrorCodes } from './errors.js';
import { RetryHandler, createRetryHandler } from './retry-handler.js';

/**
 * JWKS Cache class for efficient caching of JSON Web Key Sets from Cognito
 * Implements in-memory caching with TTL support to minimize network requests
 * Requirements: 3.1, 3.2
 */
export class JWKSCache {
  private cache: Map<string, JWKSCacheEntry> = new Map();
  private readonly TTL = 5 * 60 * 1000; // 5 minutes in milliseconds
  private retryHandler: RetryHandler;

  constructor() {
    // Initialize retry handler for network resilience
    this.retryHandler = createRetryHandler({
      maxAttempts: 3,
      baseDelay: 1000,
      maxDelay: 5000,
      requestTimeout: 10000, // 10 seconds for JWKS requests
    });
  }

  /**
   * Get JWKS keys from cache or fetch from remote endpoint
   * @param region AWS region
   * @param userPoolId Cognito User Pool ID
   * @returns Promise resolving to array of JWK keys
   */
  async getKeys(region: string, userPoolId: string): Promise<unknown[]> {
    const jwksUri = this.buildJwksUri(region, userPoolId);
    const cacheKey = jwksUri;

    // Check if we have valid cached keys
    const cached = this.cache.get(cacheKey);
    if (cached && !this.isExpired(cached.expiry)) {
      return cached.keys;
    }

    // Fetch fresh keys from Cognito JWKS endpoint
    const keys = await this.fetchKeysFromEndpoint(jwksUri);

    // Cache the keys with expiry
    const expiry = Date.now() + this.TTL;
    this.cache.set(cacheKey, { keys, expiry });

    return keys;
  }

  /**
   * Build Cognito JWKS endpoint URL dynamically
   * @param region AWS region
   * @param userPoolId Cognito User Pool ID
   * @returns JWKS endpoint URL
   */
  private buildJwksUri(region: string, userPoolId: string): string {
    return `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
  }

  /**
   * Check if cache entry has expired
   * @param expiry Expiry timestamp
   * @returns true if expired, false otherwise
   */
  private isExpired(expiry: number): boolean {
    return Date.now() > expiry;
  }

  /**
   * Fetch JWKS keys from remote endpoint with retry logic
   * @param jwksUri JWKS endpoint URL
   * @returns Promise resolving to array of JWK keys
   */
  private async fetchKeysFromEndpoint(jwksUri: string): Promise<unknown[]> {
    try {
      // Execute JWKS fetch with retry logic for network resilience
      const result = await this.retryHandler.execute(async () => {
        const response = await fetch(jwksUri);

        if (!response.ok) {
          // Throw appropriate error based on status code
          if (response.status >= 500) {
            throw new NetworkError(
              `JWKS endpoint returned server error: ${response.status} ${response.statusText}`,
              ErrorCodes.SERVICE_UNAVAILABLE
            );
          } else if (response.status === 429) {
            throw new NetworkError(
              'JWKS endpoint rate limit exceeded',
              ErrorCodes.TOO_MANY_REQUESTS
            );
          } else {
            // 4xx errors should not be retried - throw a different error type
            const error = new Error(
              `JWKS endpoint returned client error: ${response.status} ${response.statusText}`
            );
            error.name = 'ClientError';
            throw error;
          }
        }

        const jwks = (await response.json()) as { keys?: unknown[] };

        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          throw new NetworkError(
            'Invalid JWKS response: missing or invalid keys array',
            ErrorCodes.NETWORK_ERROR
          );
        }

        return jwks.keys;
      }, 'JWKS fetch operation');

      return result.result;
    } catch (error) {
      if (error instanceof NetworkError) {
        throw error;
      }

      // Handle fetch API errors
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new NetworkError(
          `Network error while fetching JWKS: ${error.message}`,
          ErrorCodes.NETWORK_ERROR
        );
      }

      throw new NetworkError(
        `JWKS fetch failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCodes.NETWORK_ERROR
      );
    }
  }

  /**
   * Clear all cached entries (useful for testing)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache size (useful for testing and monitoring)
   */
  getCacheSize(): number {
    return this.cache.size;
  }
}
