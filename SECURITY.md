# Security Policy

## Supported Versions

We actively support the following versions of @gateway/cognito-auth with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

### Built-in Security Measures

This package implements multiple layers of security to protect your application:

#### Input Validation & Sanitization
- **Comprehensive Input Validation**: All user inputs (emails, passwords, tokens, configuration) are validated using Zod schemas
- **Injection Attack Prevention**: Protection against SQL injection, XSS, and other injection attacks
- **Format Validation**: Email addresses, JWT tokens, and configuration values are validated against strict patterns
- **Length Limits**: Input length restrictions to prevent buffer overflow attacks

#### JWT Security
- **Signature Verification**: All JWT tokens are cryptographically verified using Cognito's public keys
- **Claims Validation**: Issuer, audience, and expiration claims are strictly validated
- **JWKS Caching**: Secure caching of JSON Web Key Sets with automatic expiration
- **Token Format Validation**: JWT structure and format validation before processing

#### Error Handling Security
- **Production-Safe Responses**: Generic error messages in production to prevent information disclosure
- **Sensitive Data Protection**: No exposure of tokens, secrets, or internal system details in error responses
- **Detailed Internal Logging**: Comprehensive logging for debugging without exposing sensitive data to clients
- **Stack Trace Sanitization**: Stack traces are never exposed to client responses

#### Network Security
- **Request Timeouts**: Configurable timeouts to prevent hanging connections
- **Retry Logic**: Exponential backoff for failed requests with maximum attempt limits
- **TLS/HTTPS Only**: All AWS Cognito communications use HTTPS
- **Connection Pooling**: Efficient connection management to prevent resource exhaustion

#### Configuration Security
- **Environment Variable Support**: Secure configuration loading from environment variables
- **Configuration Validation**: Runtime validation of all configuration parameters
- **Secret Management**: Proper handling of client secrets with no logging or exposure
- **Region Validation**: AWS region validation to prevent misconfiguration

### Security Best Practices

#### For Developers Using This Package

1. **Environment Variables**: Store sensitive configuration in environment variables, not in code
   ```bash
   COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
   COGNITO_CLIENT_ID=your-client-id
   COGNITO_CLIENT_SECRET=your-secret  # Only for confidential clients
   ```

2. **Token Storage**: Store JWT tokens securely on the client side
   - Use secure, httpOnly cookies for web applications
   - Use secure storage mechanisms in mobile applications
   - Never store tokens in localStorage for sensitive applications

3. **HTTPS Only**: Always use HTTPS in production environments
   ```typescript
   // Ensure your Express app uses HTTPS
   app.use((req, res, next) => {
     if (req.header('x-forwarded-proto') !== 'https') {
       res.redirect(`https://${req.header('host')}${req.url}`);
     } else {
       next();
     }
   });
   ```

4. **Token Expiration**: Configure appropriate token expiration times in Cognito
   - ID tokens: 1 hour (default)
   - Access tokens: 1 hour (default)
   - Refresh tokens: 30 days (configurable)

5. **Custom Claims Security**: Be cautious with custom claims containing sensitive data
   ```typescript
   // Good: Non-sensitive tenant identifier
   customClaims['custom:tenantId'] = 'tenant-123';
   
   // Bad: Sensitive data in claims
   customClaims['custom:creditCard'] = '4111-1111-1111-1111'; // Never do this
   ```

#### Production Deployment Security

1. **Environment Configuration**:
   ```dockerfile
   # Use build-time arguments for non-sensitive config
   ARG AWS_REGION=us-east-1
   ENV AWS_REGION=$AWS_REGION
   
   # Use runtime secrets for sensitive config
   ENV COGNITO_CLIENT_SECRET_FILE=/run/secrets/cognito_client_secret
   ```

2. **Container Security**:
   ```dockerfile
   # Run as non-root user
   RUN addgroup -g 1001 -S nodejs
   RUN adduser -S nodejs -u 1001
   USER nodejs
   
   # Use minimal base image
   FROM node:20-alpine
   ```

3. **Network Security**:
   - Use VPC endpoints for AWS services when possible
   - Implement proper firewall rules
   - Use AWS WAF for additional protection

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in @gateway/cognito-auth, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing: **security@gateway.dev**

Include the following information in your report:

1. **Description**: A clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact Assessment**: Your assessment of the potential impact
4. **Affected Versions**: Which versions of the package are affected
5. **Suggested Fix**: If you have suggestions for fixing the issue
6. **Contact Information**: How we can reach you for follow-up questions

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 24 hours
2. **Initial Assessment**: We will provide an initial assessment within 72 hours
3. **Investigation**: We will investigate the issue and determine its severity
4. **Resolution**: We will work on a fix and coordinate disclosure timing with you
5. **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

### Response Timeline

- **Critical vulnerabilities**: Patch within 7 days
- **High severity vulnerabilities**: Patch within 14 days
- **Medium severity vulnerabilities**: Patch within 30 days
- **Low severity vulnerabilities**: Patch in next regular release

### Security Advisory Process

1. We will create a private security advisory on GitHub
2. We will work with you to understand and reproduce the issue
3. We will develop and test a fix
4. We will coordinate the disclosure timeline
5. We will publish the security advisory and release the patch
6. We will notify users through appropriate channels

## Security Audit History

### Internal Security Reviews

- **December 2024**: Initial security review during development
  - Input validation implementation review
  - Error handling security assessment
  - JWT verification security analysis
  - Configuration security evaluation

### External Security Audits

No external security audits have been conducted yet. We plan to conduct regular security audits as the project grows.

## Security Dependencies

We regularly monitor and update our dependencies for security vulnerabilities:

### Dependency Security Monitoring

- **GitHub Dependabot**: Automated dependency vulnerability scanning
- **npm audit**: Regular security audits of npm dependencies
- **Snyk**: Additional vulnerability scanning (planned)

### Critical Dependencies Security

- **@aws-sdk/client-cognito-identity-provider**: Official AWS SDK with regular security updates
- **jsonwebtoken**: Well-maintained JWT library with active security monitoring
- **jwks-rsa**: Trusted JWKS handling library with security focus
- **zod**: Type-safe validation library with security considerations

## Security Configuration

### Recommended Cognito Security Settings

1. **User Pool Configuration**:
   - Enable MFA for sensitive applications
   - Configure strong password policies
   - Set appropriate token expiration times
   - Enable advanced security features (risk-based authentication)

2. **App Client Configuration**:
   - Use confidential clients for server-side applications
   - Configure appropriate OAuth scopes
   - Enable refresh token rotation
   - Set appropriate redirect URIs

3. **Lambda Triggers**:
   - Validate custom claims in Pre Token Generation triggers
   - Implement additional security checks in authentication triggers
   - Log security events for monitoring

### Environment Security Checklist

- [ ] All sensitive configuration stored in environment variables
- [ ] HTTPS enforced in production
- [ ] Proper error handling implemented
- [ ] Security headers configured
- [ ] Logging configured without sensitive data exposure
- [ ] Token storage security implemented
- [ ] Network security measures in place
- [ ] Regular security updates scheduled

## Contact

For security-related questions or concerns:

- **Security Email**: security@gateway.dev
- **General Support**: support@gateway.dev
- **GitHub Issues**: For non-security related issues only

---

**Remember**: Security is a shared responsibility. While this package implements security best practices, the overall security of your application depends on proper implementation and deployment practices.