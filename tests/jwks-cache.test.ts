// Tests for jwks-cache.ts
// Requirements: 3.1, 3.2

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { JWKSCache } from '../src/jwks-cache.js';
import { NetworkError } from '../src/errors.js';

describe('JWKSCache', () => {
  let jwksCache: JWKSCache;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    jwksCache = new JWKSCache();

    // Mock global fetch
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create a new JWKSCache instance', () => {
      expect(jwksCache).toBeDefined();
      expect(jwksCache.getCacheSize()).toBe(0);
    });
  });

  describe('getKeys', () => {
    it('should fetch keys from Cognito JWKS endpoint', async () => {
      const mockKeys = [
        { kid: 'key1', kty: 'RSA', use: 'sig', n: 'abc', e: 'AQAB' },
        { kid: 'key2', kty: 'RSA', use: 'sig', n: 'def', e: 'AQAB' },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ keys: mockKeys }),
      });

      const keys = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');

      expect(keys).toEqual(mockKeys);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test123/.well-known/jwks.json'
      );
    });

    it('should return cached keys on subsequent calls', async () => {
      const mockKeys = [{ kid: 'key1', kty: 'RSA' }];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ keys: mockKeys }),
      });

      // First call - should fetch
      const keys1 = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(keys1).toEqual(mockKeys);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const keys2 = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(keys2).toEqual(mockKeys);
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still just 1 call
    });

    it('should fetch different keys for different regions', async () => {
      const mockKeysEast = [{ kid: 'east-key' }];
      const mockKeysWest = [{ kid: 'west-key' }];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ keys: mockKeysEast }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ keys: mockKeysWest }),
        });

      const keysEast = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      const keysWest = await jwksCache.getKeys('us-west-2', 'us-west-2_test456');

      expect(keysEast).toEqual(mockKeysEast);
      expect(keysWest).toEqual(mockKeysWest);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should throw NetworkError on 5xx server error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      });

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow(
        NetworkError
      );
    });

    it('should throw NetworkError on 429 rate limit', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
      });

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow(
        NetworkError
      );
    });

    it('should throw error on 4xx client errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow();
    });

    it('should throw NetworkError on invalid JWKS response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}), // Missing keys array
      });

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow(
        NetworkError
      );
    });

    it('should throw NetworkError on non-array keys', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ keys: 'not an array' }),
      });

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow(
        NetworkError
      );
    });

    it('should throw NetworkError on network failure', async () => {
      const fetchError = new TypeError('fetch failed: Network error');
      mockFetch.mockRejectedValue(fetchError);

      await expect(jwksCache.getKeys('us-east-1', 'us-east-1_test123')).rejects.toThrow(
        NetworkError
      );
    });
  });

  describe('clearCache', () => {
    it('should clear all cached entries', async () => {
      const mockKeys = [{ kid: 'key1' }];

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: mockKeys }),
      });

      // Populate cache
      await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(jwksCache.getCacheSize()).toBe(1);

      // Clear cache
      jwksCache.clearCache();
      expect(jwksCache.getCacheSize()).toBe(0);
    });
  });

  describe('getCacheSize', () => {
    it('should return 0 for new cache', () => {
      expect(jwksCache.getCacheSize()).toBe(0);
    });

    it('should return correct count after caching', async () => {
      const mockKeys = [{ kid: 'key1' }];

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: mockKeys }),
      });

      await jwksCache.getKeys('us-east-1', 'us-east-1_pool1');
      expect(jwksCache.getCacheSize()).toBe(1);

      await jwksCache.getKeys('us-west-2', 'us-west-2_pool2');
      expect(jwksCache.getCacheSize()).toBe(2);
    });
  });

  describe('cache expiry', () => {
    it('should refetch keys after TTL expires', async () => {
      vi.useFakeTimers();

      const mockKeys1 = [{ kid: 'key1' }];
      const mockKeys2 = [{ kid: 'key2' }];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ keys: mockKeys1 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ keys: mockKeys2 }),
        });

      // First fetch
      const keys1 = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(keys1).toEqual(mockKeys1);

      // Advance time past TTL (5 minutes)
      vi.advanceTimersByTime(6 * 60 * 1000);

      // Should fetch again due to expiry
      const keys2 = await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(keys2).toEqual(mockKeys2);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });

    it('should use cache before TTL expires', async () => {
      vi.useFakeTimers();

      const mockKeys = [{ kid: 'key1' }];

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: mockKeys }),
      });

      // First fetch
      await jwksCache.getKeys('us-east-1', 'us-east-1_test123');

      // Advance time but not past TTL (less than 5 minutes)
      vi.advanceTimersByTime(4 * 60 * 1000);

      // Should use cache
      await jwksCache.getKeys('us-east-1', 'us-east-1_test123');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      vi.useRealTimers();
    });
  });

  describe('JWKS URI construction', () => {
    it('should build correct JWKS URI for different regions', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: [] }),
      });

      await jwksCache.getKeys('eu-west-1', 'eu-west-1_abc123');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc123/.well-known/jwks.json'
      );
    });

    it('should build correct JWKS URI for ap-southeast', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: [] }),
      });

      await jwksCache.getKeys('ap-southeast-1', 'ap-southeast-1_xyz789');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_xyz789/.well-known/jwks.json'
      );
    });
  });
});
