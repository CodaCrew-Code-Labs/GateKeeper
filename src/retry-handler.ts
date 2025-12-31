// Network retry handling utilities
// Requirements: 6.4

import { NetworkError, ErrorCodes } from './errors.js';

/**
 * Configuration for retry behavior
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxAttempts?: number;
  /** Base delay between retries in milliseconds */
  baseDelay?: number;
  /** Maximum delay between retries in milliseconds */
  maxDelay?: number;
  /** Multiplier for exponential backoff */
  backoffMultiplier?: number;
  /** Whether to add jitter to delays */
  enableJitter?: boolean;
  /** Timeout for individual requests in milliseconds */
  requestTimeout?: number;
  /** Function to determine if error should be retried */
  shouldRetry?: (error: unknown, attempt: number) => boolean;
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: Required<RetryConfig> = {
  maxAttempts: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 30000, // 30 seconds
  backoffMultiplier: 2,
  enableJitter: true,
  requestTimeout: 30000, // 30 seconds
  shouldRetry: (error: unknown, _attempt: number) => {
    // Retry on network errors, timeouts, and 5xx status codes
    if (error instanceof NetworkError) {
      return true;
    }

    // Check for AWS SDK network errors
    if (error && typeof error === 'object' && 'name' in error) {
      const awsError = error as { name: string; $metadata?: unknown };
      const retryableErrors = [
        'NetworkingError',
        'TimeoutError',
        'ServiceUnavailableException',
        'InternalErrorException',
        'ThrottlingException',
        'TooManyRequestsException',
      ];

      if (retryableErrors.includes(awsError.name)) {
        return true;
      }

      // Check HTTP status codes in metadata
      if (
        awsError.$metadata &&
        typeof awsError.$metadata === 'object' &&
        'httpStatusCode' in awsError.$metadata
      ) {
        const statusCode = (awsError.$metadata as { httpStatusCode: number }).httpStatusCode;
        return statusCode >= 500 || statusCode === 429; // 5xx or rate limiting
      }
    }

    // Check for standard network errors
    if (error instanceof Error) {
      const networkErrorMessages = [
        'ECONNRESET',
        'ECONNREFUSED',
        'ETIMEDOUT',
        'ENOTFOUND',
        'EAI_AGAIN',
        'EPIPE',
        'ECONNABORTED',
      ];

      return networkErrorMessages.some(
        msg => error.message.includes(msg) || error.name.includes(msg)
      );
    }

    return false;
  },
};

/**
 * Retry statistics for monitoring
 */
export interface RetryStats {
  totalAttempts: number;
  successfulAttempt: number;
  totalDelay: number;
  errors: Array<{
    attempt: number;
    error: string;
    delay: number;
  }>;
}

/**
 * Result of retry operation
 */
export interface RetryResult<T> {
  result: T;
  stats: RetryStats;
}

/**
 * Network retry handler utility
 * Implements exponential backoff with jitter for transient failures
 * Requirements: 6.4
 */
export class RetryHandler {
  private config: Required<RetryConfig>;

  constructor(config: RetryConfig = {}) {
    this.config = {
      ...DEFAULT_RETRY_CONFIG,
      ...config,
    };
  }

  /**
   * Execute operation with retry logic
   * Requirements: 6.4
   *
   * @param operation Async operation to execute
   * @param context Optional context for error reporting
   * @returns Promise resolving to operation result with retry stats
   */
  async execute<T>(operation: () => Promise<T>, context?: string): Promise<RetryResult<T>> {
    const stats: RetryStats = {
      totalAttempts: 0,
      successfulAttempt: 0,
      totalDelay: 0,
      errors: [],
    };

    let lastError: unknown;

    for (let attempt = 1; attempt <= this.config.maxAttempts; attempt++) {
      stats.totalAttempts = attempt;

      try {
        // Add timeout wrapper to the operation
        const result = await this.withTimeout(operation(), this.config.requestTimeout);
        stats.successfulAttempt = attempt;
        return { result, stats };
      } catch (error) {
        lastError = error;

        // Check if we should retry this error
        if (!this.config.shouldRetry(error, attempt)) {
          throw this.wrapError(error, context, stats);
        }

        // Don't retry on the last attempt
        if (attempt === this.config.maxAttempts) {
          break;
        }

        // Calculate delay for next attempt
        const delay = this.calculateDelay(attempt);
        stats.totalDelay += delay;
        stats.errors.push({
          attempt,
          error: error instanceof Error ? error.message : String(error),
          delay,
        });

        // Wait before next attempt
        await this.sleep(delay);
      }
    }

    // All retries exhausted
    throw this.wrapError(lastError, context, stats);
  }

  /**
   * Execute operation with timeout
   * @param operation Promise to execute
   * @param timeout Timeout in milliseconds
   * @returns Promise that rejects on timeout
   */
  private async withTimeout<T>(operation: Promise<T>, timeout: number): Promise<T> {
    return Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new NetworkError(`Operation timed out after ${timeout}ms`, ErrorCodes.TIMEOUT));
        }, timeout);
      }),
    ]);
  }

  /**
   * Calculate delay for exponential backoff with jitter
   * @param attempt Current attempt number (1-based)
   * @returns Delay in milliseconds
   */
  private calculateDelay(attempt: number): number {
    // Exponential backoff: baseDelay * (backoffMultiplier ^ (attempt - 1))
    const exponentialDelay =
      this.config.baseDelay * Math.pow(this.config.backoffMultiplier, attempt - 1);

    // Cap at maximum delay
    let delay = Math.min(exponentialDelay, this.config.maxDelay);

    // Add jitter to prevent thundering herd
    if (this.config.enableJitter) {
      // Add random jitter of ±25%
      const jitterRange = delay * 0.25;
      const jitter = (Math.random() - 0.5) * 2 * jitterRange;
      delay = Math.max(0, delay + jitter);
    }

    return Math.round(delay);
  }

  /**
   * Sleep for specified duration
   * @param ms Duration in milliseconds
   * @returns Promise that resolves after delay
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Wrap error with retry context information
   * @param error Original error
   * @param context Operation context
   * @param stats Retry statistics
   * @returns Wrapped error with additional context
   */
  private wrapError(error: unknown, context?: string, stats?: RetryStats): NetworkError {
    const baseMessage = error instanceof Error ? error.message : String(error);
    const contextMessage = context ? ` (${context})` : '';
    const statsMessage = stats
      ? ` after ${stats.totalAttempts} attempts over ${stats.totalDelay}ms`
      : '';

    const message = `Network operation failed${contextMessage}${statsMessage}: ${baseMessage}`;

    const networkError = new NetworkError(message, ErrorCodes.NETWORK_ERROR);

    // Add additional properties using type assertion
    (
      networkError as NetworkError & { originalError: unknown; retryStats?: RetryStats }
    ).originalError = error;
    if (stats) {
      (
        networkError as NetworkError & { originalError: unknown; retryStats?: RetryStats }
      ).retryStats = stats;
    }

    return networkError;
  }

  /**
   * Update retry configuration
   * @param config New configuration options
   */
  public updateConfig(config: Partial<RetryConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    };
  }

  /**
   * Get current configuration
   * @returns Current retry configuration
   */
  public getConfig(): Readonly<Required<RetryConfig>> {
    return { ...this.config };
  }
}

/**
 * Default retry handler instance
 */
export const defaultRetryHandler = new RetryHandler();

/**
 * Convenience function to execute operation with default retry logic
 * @param operation Async operation to execute
 * @param context Optional context for error reporting
 * @returns Promise resolving to operation result
 */
export async function withRetry<T>(operation: () => Promise<T>, context?: string): Promise<T> {
  const result = await defaultRetryHandler.execute(operation, context);
  return result.result;
}

/**
 * Create retry handler with custom configuration
 * @param config Retry configuration
 * @returns Configured retry handler instance
 */
export function createRetryHandler(config: RetryConfig): RetryHandler {
  return new RetryHandler(config);
}

/**
 * Execute operation with custom retry configuration
 * @param operation Async operation to execute
 * @param config Retry configuration
 * @param context Optional context for error reporting
 * @returns Promise resolving to operation result
 */
export async function withCustomRetry<T>(
  operation: () => Promise<T>,
  config: RetryConfig,
  context?: string
): Promise<T> {
  const retryHandler = new RetryHandler(config);
  const result = await retryHandler.execute(operation, context);
  return result.result;
}

/**
 * Check if error is retryable using default configuration
 * @param error Error to check
 * @param attempt Current attempt number
 * @returns True if error should be retried
 */
export function isRetryableError(error: unknown, attempt: number = 1): boolean {
  return DEFAULT_RETRY_CONFIG.shouldRetry(error, attempt);
}
