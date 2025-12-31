// Express middleware for JWT authentication
// Requirements: 2.1, 2.2, 2.6

import { Request, Response, NextFunction, RequestHandler } from 'express';
import { CognitoConfig, AuthMiddlewareOptions, AuthenticatedRequest } from './types.js';
import { JWTVerifier } from './jwt-verification.js';
import { InvalidTokenError } from './errors.js';
import { validateAuthorizationHeader, validateJWTToken } from './validation.js';
import { createErrorHandler } from './error-handler.js';

/**
 * Create authentication middleware for Express applications
 * Extracts Bearer tokens from Authorization headers and verifies them using JWT verification
 * Requirements: 2.1, 2.2, 2.6
 *
 * @param config Cognito configuration
 * @param options Middleware options
 * @returns Express middleware function
 */
export function createAuthMiddleware(
  config: CognitoConfig,
  options: AuthMiddlewareOptions
): RequestHandler {
  const jwtVerifier = new JWTVerifier(config);
  const errorHandler = createErrorHandler({
    environment: (process.env.NODE_ENV as 'production' | 'development' | 'test') || 'production',
    enableLogging: true,
  });

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Skip verification if option is set (for development)
      if (options.skipVerification) {
        // In skip mode, we still try to extract user info but don't fail on errors
        const token = extractBearerToken(req);
        if (token) {
          try {
            const userInfo = await jwtVerifier.verifyToken(token, options.tokenUse);
            (req as AuthenticatedRequest).user = userInfo;
          } catch {
            // Silently ignore verification errors in skip mode
            (req as AuthenticatedRequest).user = {
              sub: 'dev-user',
              email: 'dev@example.com',
              customClaims: {},
            };
          }
        } else {
          // Provide default user in skip mode when no token present
          (req as AuthenticatedRequest).user = {
            sub: 'dev-user',
            email: 'dev@example.com',
            customClaims: {},
          };
        }
        return next();
      }

      // Extract Bearer token from Authorization header
      const token = extractBearerToken(req);
      if (!token) {
        const { response, statusCode } = errorHandler.handleError(
          new InvalidTokenError('Missing or invalid Authorization header', 'MISSING_TOKEN'),
          { operation: 'middleware', path: req.path }
        );
        res.status(statusCode).json(response);
        return;
      }

      // Verify JWT token and extract user information
      const userInfo = await jwtVerifier.verifyToken(token, options.tokenUse);

      // Attach user information to request object
      (req as AuthenticatedRequest).user = userInfo;

      next();
    } catch (error) {
      // Use error handler for production-safe error responses
      const { response, statusCode } = errorHandler.handleError(error, {
        operation: 'middleware',
        path: req.path,
        method: req.method,
      });

      res.status(statusCode).json(response);
      return;
    }
  };
}

/**
 * Extract Bearer token from Authorization header with comprehensive validation
 * Requirements: 2.1, 2.3
 *
 * @param req Express request object
 * @returns JWT token string or null if not found/invalid
 */
export function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;

  // Validate authorization header format and security
  const validatedHeader = validateAuthorizationHeader(authHeader);
  if (!validatedHeader) {
    return null;
  }

  // Extract token part (everything after 'Bearer ')
  const token = validatedHeader.substring(7).trim();

  // Validate token is not empty
  if (!token) {
    return null;
  }

  try {
    // Validate JWT token format and security
    return validateJWTToken(token);
  } catch {
    // Invalid token format
    return null;
  }
}

/**
 * Type guard to check if request has authenticated user
 * @param req Express request object
 * @returns true if request has user property
 */
export function isAuthenticatedRequest(req: Request): req is AuthenticatedRequest {
  return 'user' in req && req.user !== undefined;
}
