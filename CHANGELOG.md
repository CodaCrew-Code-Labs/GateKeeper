# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-31

### Added

#### Core Authentication Features
- **CognitoAuthManager** class with complete AWS Cognito integration
- User signup with email/password authentication
- Email verification with confirmation codes
- User login with credential validation
- JWT token refresh functionality
- Automatic secret hash computation for confidential app clients

#### Express Middleware Integration
- **authMiddleware** for JWT token verification
- Bearer token extraction from Authorization headers
- Support for both ID and Access token verification
- User information attachment to `req.user` object
- Development mode with `skipVerification` option

#### Security & Validation
- Comprehensive input validation and sanitization
- Protection against injection attacks
- Production-safe error handling with generic client responses
- Detailed internal logging for debugging
- Custom error classes with specific error codes

#### Multi-Tenant Support
- Custom claims extraction from JWT tokens
- Support for `custom:tenantId` and arbitrary custom claims
- Graceful handling of missing custom claims
- Type-safe access to tenant information

#### Performance Optimizations
- **JWKS caching** with 5-minute TTL
- Efficient JWT signature verification
- Minimal network requests to Cognito endpoints
- In-memory cache with automatic expiration

#### Developer Experience
- **Full TypeScript support** with comprehensive type definitions
- **Dual package exports** (CommonJS and ESM)
- Tree-shaking compatibility for optimal bundle sizes
- Environment variable-based configuration
- Zod schema validation for runtime type safety

#### Testing & Quality
- **95%+ code coverage** across all modules
- **Property-based testing** with fast-check
- Unit tests for specific examples and edge cases
- LocalStack integration for local development
- Comprehensive error condition testing

#### Build & Distribution
- Dual build system (CommonJS/ESM)
- TypeScript declaration files
- Node.js 20+ compatibility
- Docker/container environment support
- GitHub Actions CI/CD pipeline

#### Documentation & Examples
- Comprehensive README with API documentation
- Working Express application example
- Configuration reference tables
- Multi-tenant usage patterns
- Docker deployment examples

### Technical Details

#### Dependencies
- `@aws-sdk/client-cognito-identity-provider` ^3.0.0 - AWS Cognito SDK
- `jsonwebtoken` ^9.0.0 - JWT token handling
- `jwks-rsa` ^3.0.0 - JWKS key retrieval and caching
- `zod` ^3.22.0 - Runtime schema validation

#### Peer Dependencies
- `express` ^4.18.0 - Web framework for middleware functionality

#### Development Dependencies
- `typescript` ^5.3.0 - TypeScript compiler
- `vitest` ^1.0.0 - Testing framework
- `fast-check` ^3.15.0 - Property-based testing
- `@vitest/coverage-v8` ^1.0.0 - Code coverage
- `eslint` ^8.0.0 - Code linting
- `prettier` ^3.0.0 - Code formatting

#### Supported Environments
- Node.js 20.0.0 or higher
- CommonJS and ES modules
- Docker and containerized environments
- AWS Lambda and serverless platforms
- Express.js web applications

### Security Considerations

- All user inputs are validated and sanitized
- JWT tokens are verified using Cognito's public keys
- Secret hash computation follows AWS specifications
- Error responses don't expose sensitive information
- Network requests include timeout and retry logic
- Custom claims are safely extracted and typed

### Breaking Changes

This is the initial release, so no breaking changes apply.

### Migration Guide

This is the initial release. For new installations:

1. Install the package: `npm install @gateway/cognito-auth`
2. Configure environment variables or pass config object
3. Create CognitoAuthManager instance
4. Use authMiddleware for route protection
5. Access user information via `req.user`

### Known Issues

None at this time.

### Deprecations

None at this time.

---

## Release Notes Template

For future releases, use this template:

## [Unreleased]

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Bug fixes

### Security
- Security improvements

---

## Version History

- **1.0.0** - Initial release with complete Cognito authentication functionality