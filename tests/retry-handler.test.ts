// Tests for retry-handler.ts
// Requirements: 6.4

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  RetryHandler,
  createRetryHandler,
  withRetry,
  withCustomRetry,
  isRetryableError,
  DEFAULT_RETRY_CONFIG,
  defaultRetryHandler,
} from '../src/retry-handler.js';
import { NetworkError, ErrorCodes } from '../src/errors.js';

describe('RetryHandler', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor and configuration', () => {
    it('should create with default configuration', () => {
      const handler = new RetryHandler();
      const config = handler.getConfig();

      expect(config.maxAttempts).toBe(3);
      expect(config.baseDelay).toBe(1000);
      expect(config.maxDelay).toBe(30000);
      expect(config.backoffMultiplier).toBe(2);
      expect(config.enableJitter).toBe(true);
    });

    it('should create with custom configuration', () => {
      const handler = new RetryHandler({
        maxAttempts: 5,
        baseDelay: 500,
        maxDelay: 10000,
      });
      const config = handler.getConfig();

      expect(config.maxAttempts).toBe(5);
      expect(config.baseDelay).toBe(500);
      expect(config.maxDelay).toBe(10000);
    });

    it('should update configuration', () => {
      const handler = new RetryHandler();
      handler.updateConfig({ maxAttempts: 10 });
      const config = handler.getConfig();

      expect(config.maxAttempts).toBe(10);
    });
  });

  describe('execute with successful operations', () => {
    it('should return result on first successful attempt', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({ maxAttempts: 3 });
      const operation = vi.fn().mockResolvedValue('success');

      const result = await handler.execute(operation);

      expect(result.result).toBe('success');
      expect(result.stats.totalAttempts).toBe(1);
      expect(result.stats.successfulAttempt).toBe(1);
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should return stats with zero total delay on first success', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler();
      const operation = vi.fn().mockResolvedValue('data');

      const result = await handler.execute(operation);

      expect(result.stats.totalDelay).toBe(0);
      expect(result.stats.errors).toHaveLength(0);
    });
  });

  describe('execute with retries', () => {
    it('should retry on retryable errors and eventually succeed', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 3,
        baseDelay: 10,
        enableJitter: false,
      });
      const operation = vi
        .fn()
        .mockRejectedValueOnce(new NetworkError('Temporary failure', ErrorCodes.NETWORK_ERROR))
        .mockResolvedValueOnce('success');

      const result = await handler.execute(operation);

      expect(result.result).toBe('success');
      expect(result.stats.totalAttempts).toBe(2);
      expect(result.stats.successfulAttempt).toBe(2);
      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('should fail after max attempts exhausted', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 2,
        baseDelay: 10,
        enableJitter: false,
      });
      const operation = vi
        .fn()
        .mockRejectedValue(new NetworkError('Permanent failure', ErrorCodes.NETWORK_ERROR));

      await expect(handler.execute(operation)).rejects.toThrow(NetworkError);
      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('should not retry non-retryable errors', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({ maxAttempts: 3 });
      const nonRetryableError = new Error('Non-retryable error');
      const operation = vi.fn().mockRejectedValue(nonRetryableError);

      await expect(handler.execute(operation)).rejects.toThrow(NetworkError);
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should include context in wrapped error', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({ maxAttempts: 1 });
      const operation = vi.fn().mockRejectedValue(new Error('fail'));

      try {
        await handler.execute(operation, 'test operation');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(NetworkError);
        expect((error as Error).message).toContain('test operation');
      }
    });

    it('should record retry statistics', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 3,
        baseDelay: 10,
        enableJitter: false,
      });
      const operation = vi
        .fn()
        .mockRejectedValueOnce(new NetworkError('Error 1', ErrorCodes.NETWORK_ERROR))
        .mockRejectedValueOnce(new NetworkError('Error 2', ErrorCodes.NETWORK_ERROR))
        .mockResolvedValueOnce('success');

      const result = await handler.execute(operation);

      expect(result.stats.errors).toHaveLength(2);
      expect(result.stats.totalDelay).toBeGreaterThan(0);
    });
  });

  describe('timeout handling', () => {
    it('should timeout slow operations', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 1,
        requestTimeout: 50, // Very short timeout for testing
      });
      const slowOperation = (): Promise<string> =>
        new Promise(resolve => {
          setTimeout(() => resolve('done'), 500);
        });

      // This should timeout
      await expect(handler.execute(slowOperation)).rejects.toThrow('timed out');
    });
  });

  describe('delay calculation', () => {
    it('should calculate exponential backoff correctly', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 4,
        baseDelay: 100,
        backoffMultiplier: 2,
        enableJitter: false, // Disable jitter for predictable testing
      });

      const operation = vi
        .fn()
        .mockRejectedValueOnce(new NetworkError('Error 1', ErrorCodes.NETWORK_ERROR))
        .mockRejectedValueOnce(new NetworkError('Error 2', ErrorCodes.NETWORK_ERROR))
        .mockRejectedValueOnce(new NetworkError('Error 3', ErrorCodes.NETWORK_ERROR))
        .mockResolvedValueOnce('success');

      const result = await handler.execute(operation);

      // Check delays are exponential: 100, 200, 400, ...
      expect(result.stats.errors[0].delay).toBe(100);
      expect(result.stats.errors[1].delay).toBe(200);
      expect(result.stats.errors[2].delay).toBe(400);
    });

    it('should cap delay at maxDelay', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 5,
        baseDelay: 1000,
        maxDelay: 1500,
        backoffMultiplier: 2,
        enableJitter: false,
      });

      const operation = vi
        .fn()
        .mockRejectedValueOnce(new NetworkError('Error', ErrorCodes.NETWORK_ERROR))
        .mockRejectedValueOnce(new NetworkError('Error', ErrorCodes.NETWORK_ERROR))
        .mockResolvedValueOnce('success');

      const result = await handler.execute(operation);

      // Second delay should be capped at 1500, not 2000
      expect(result.stats.errors[1].delay).toBe(1500);
    });

    it('should add jitter when enabled', async () => {
      vi.useRealTimers();
      const handler = new RetryHandler({
        maxAttempts: 3,
        baseDelay: 1000,
        enableJitter: true,
      });

      const operation = vi
        .fn()
        .mockRejectedValueOnce(new NetworkError('Error', ErrorCodes.NETWORK_ERROR))
        .mockResolvedValueOnce('success');

      const result = await handler.execute(operation);

      // Delay should be around 1000 ms +/- 25%
      expect(result.stats.errors[0].delay).toBeGreaterThanOrEqual(750);
      expect(result.stats.errors[0].delay).toBeLessThanOrEqual(1250);
    });
  });
});

describe('isRetryableError', () => {
  it('should return true for NetworkError', () => {
    const error = new NetworkError('Network fail', ErrorCodes.NETWORK_ERROR);
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS NetworkingError', () => {
    const error = { name: 'NetworkingError' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS TimeoutError', () => {
    const error = { name: 'TimeoutError' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS ServiceUnavailableException', () => {
    const error = { name: 'ServiceUnavailableException' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS ThrottlingException', () => {
    const error = { name: 'ThrottlingException' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS TooManyRequestsException', () => {
    const error = { name: 'TooManyRequestsException' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for AWS InternalErrorException', () => {
    const error = { name: 'InternalErrorException' };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for 5xx status codes in metadata', () => {
    const error = { name: 'SomeError', $metadata: { httpStatusCode: 503 } };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for 429 status code in metadata', () => {
    const error = { name: 'SomeError', $metadata: { httpStatusCode: 429 } };
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return false for 4xx status codes in metadata (except 429)', () => {
    const error = { name: 'SomeError', $metadata: { httpStatusCode: 400 } };
    expect(isRetryableError(error)).toBe(false);
  });

  it('should return true for ECONNRESET errors', () => {
    const error = new Error('Connection reset: ECONNRESET');
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for ETIMEDOUT errors', () => {
    const error = new Error('Operation timed out: ETIMEDOUT');
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for ECONNREFUSED errors', () => {
    const error = new Error('Connection refused: ECONNREFUSED');
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for ENOTFOUND errors', () => {
    const error = new Error('Host not found: ENOTFOUND');
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return true for EAI_AGAIN errors', () => {
    const error = new Error('DNS lookup failed: EAI_AGAIN');
    expect(isRetryableError(error)).toBe(true);
  });

  it('should return false for regular errors', () => {
    const error = new Error('Regular error');
    expect(isRetryableError(error)).toBe(false);
  });

  it('should return false for null', () => {
    expect(isRetryableError(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isRetryableError(undefined)).toBe(false);
  });
});

describe('convenience functions', () => {
  it('should export defaultRetryHandler', () => {
    expect(defaultRetryHandler).toBeInstanceOf(RetryHandler);
  });

  it('should export createRetryHandler function', () => {
    const handler = createRetryHandler({ maxAttempts: 5 });
    expect(handler).toBeInstanceOf(RetryHandler);
    expect(handler.getConfig().maxAttempts).toBe(5);
  });

  it('should export withRetry function', async () => {
    const operation = vi.fn().mockResolvedValue('result');
    const result = await withRetry(operation);
    expect(result).toBe('result');
  });

  it('should export withCustomRetry function', async () => {
    const operation = vi.fn().mockResolvedValue('result');
    const result = await withCustomRetry(operation, { maxAttempts: 2 });
    expect(result).toBe('result');
  });
});

describe('DEFAULT_RETRY_CONFIG', () => {
  it('should have expected default values', () => {
    expect(DEFAULT_RETRY_CONFIG.maxAttempts).toBe(3);
    expect(DEFAULT_RETRY_CONFIG.baseDelay).toBe(1000);
    expect(DEFAULT_RETRY_CONFIG.maxDelay).toBe(30000);
    expect(DEFAULT_RETRY_CONFIG.backoffMultiplier).toBe(2);
    expect(DEFAULT_RETRY_CONFIG.enableJitter).toBe(true);
    expect(DEFAULT_RETRY_CONFIG.requestTimeout).toBe(30000);
    expect(typeof DEFAULT_RETRY_CONFIG.shouldRetry).toBe('function');
  });
});
