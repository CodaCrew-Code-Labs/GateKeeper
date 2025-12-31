# @gateway/cognito-auth Example Application

This example demonstrates how to integrate the `@gateway/cognito-auth` package into an Express.js application. It showcases all the key features including user authentication, JWT middleware, multi-tenant support, and error handling.

## Features Demonstrated

- ✅ **User Authentication Flow**: Signup, confirmation, login, and token refresh
- ✅ **JWT Middleware Integration**: Protect routes with automatic token verification
- ✅ **Multi-Tenant Support**: Extract and use custom claims for tenant isolation
- ✅ **Error Handling**: Production-safe error responses with detailed logging
- ✅ **Development Mode**: Skip verification for development environments
- ✅ **Multiple Token Types**: Support for both ID tokens and access tokens

## Quick Start

### 1. Setup Environment

Copy the environment template and configure your AWS Cognito settings:

```bash
cp .env.example .env
```

Edit `.env` with your actual Cognito configuration:

```env
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret-if-applicable
AWS_REGION=us-east-1
PORT=3000
NODE_ENV=development
```

### 2. Build and Install

```bash
# Build the parent package and install dependencies
npm run setup

# Or manually:
cd .. && npm run build
cd example && npm install
```

### 3. Start the Server

```bash
npm start
# or for development with auto-reload:
npm run dev
```

### 4. Test the API

```bash
# Run the test script to see all endpoints in action
npm run test-endpoints
```

## API Endpoints

### Public Endpoints (No Authentication Required)

#### `GET /`
Health check and API documentation.

**Response:**
```json
{
  "message": "AWS Cognito Authentication Example API",
  "version": "1.0.0",
  "endpoints": { ... }
}
```

#### `POST /auth/signup`
Create a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "message": "User created successfully. Please check your email for verification code.",
  "userSub": "12345678-1234-1234-1234-123456789012"
}
```

#### `POST /auth/confirm`
Confirm user signup with verification code.

**Request:**
```json
{
  "username": "user@example.com",
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "Account confirmed successfully. You can now log in."
}
```

#### `POST /auth/login`
Authenticate user and receive JWT tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "tokens": {
    "idToken": "eyJhbGciOiJSUzI1NiIs...",
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs..."
  }
}
```

#### `POST /auth/refresh`
Refresh expired tokens.

**Request:**
```json
{
  "refreshToken": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Response:**
```json
{
  "message": "Tokens refreshed successfully",
  "tokens": {
    "idToken": "eyJhbGciOiJSUzI1NiIs...",
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs..."
  }
}
```

### Protected Endpoints (Authentication Required)

All protected endpoints require an `Authorization: Bearer <token>` header.

#### `GET /profile`
Get user profile information (uses ID token middleware).

**Headers:**
```
Authorization: Bearer <idToken>
```

**Response:**
```json
{
  "message": "User profile retrieved successfully",
  "user": {
    "sub": "12345678-1234-1234-1234-123456789012",
    "email": "user@example.com",
    "customClaims": {
      "custom:tenantId": "tenant-123",
      "custom:role": "admin"
    }
  }
}
```

#### `GET /admin/users`
Admin endpoint (uses access token middleware).

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "message": "Admin endpoint accessed successfully",
  "user": { ... },
  "data": {
    "totalUsers": 42,
    "activeUsers": 38
  }
}
```

#### `GET /tenant/info`
Multi-tenant endpoint demonstrating custom claims usage.

**Headers:**
```
Authorization: Bearer <idToken>
```

**Response:**
```json
{
  "message": "Tenant information retrieved successfully",
  "tenant": {
    "id": "tenant-123",
    "name": "Tenant tenant-123",
    "plan": "premium"
  },
  "user": {
    "sub": "12345678-1234-1234-1234-123456789012",
    "email": "user@example.com",
    "role": "admin"
  }
}
```

#### `GET /dev/test`
Development endpoint that skips verification in development mode.

**Response:**
```json
{
  "message": "Development endpoint accessed",
  "note": "This endpoint skips JWT verification in development mode",
  "user": { ... },
  "environment": "development"
}
```

## Multi-Tenant Configuration

This example demonstrates how to use custom JWT claims for multi-tenant applications:

### Custom Claims Structure

The package automatically extracts all `custom:*` claims from JWT tokens:

```json
{
  "custom:tenantId": "tenant-123",
  "custom:role": "admin",
  "custom:plan": "premium",
  "custom:permissions": "read,write,delete"
}
```

### Accessing Custom Claims

In your route handlers, access custom claims through `req.user.customClaims`:

```javascript
app.get('/tenant-data', authMiddleware, (req, res) => {
  const tenantId = req.user.customClaims?.['custom:tenantId'];
  const userRole = req.user.customClaims?.['custom:role'];
  
  if (!tenantId) {
    return res.status(403).json({ error: 'No tenant access' });
  }
  
  // Fetch tenant-specific data
  const data = getTenantData(tenantId, userRole);
  res.json(data);
});
```

## Error Handling

The example demonstrates production-safe error handling:

### Client Responses
- Generic error messages that don't expose sensitive information
- Appropriate HTTP status codes (400, 401, 403, 500)
- Consistent error response format

### Server Logging
- Detailed error information logged to console
- Request context for debugging
- No sensitive data in logs

### Example Error Response
```json
{
  "error": "Invalid email or password"
}
```

## Development vs Production

### Development Mode
- Set `NODE_ENV=development` in your `.env` file
- The `/dev/test` endpoint skips JWT verification
- More detailed error messages in logs

### Production Mode
- Set `NODE_ENV=production`
- All endpoints require valid JWT tokens
- Generic error messages to clients
- Detailed logging for debugging

## Testing Without Real Cognito

You can test the API structure without configuring real AWS Cognito:

1. Start the server (it will show configuration warnings)
2. Run `npm run test-endpoints` to see all endpoints
3. Authentication endpoints will fail gracefully with appropriate error messages
4. Development endpoints will work if `NODE_ENV=development`

## Integration Patterns

### Basic Authentication
```javascript
const { CognitoAuthManager } = require('@gateway/cognito-auth');

const authManager = new CognitoAuthManager({
  userPoolId: process.env.COGNITO_USER_POOL_ID,
  clientId: process.env.COGNITO_CLIENT_ID,
  clientSecret: process.env.COGNITO_CLIENT_SECRET, // Optional
  region: process.env.AWS_REGION
});

// Use middleware
app.use('/protected', authManager.authMiddleware({ tokenUse: 'id' }));
```

### Custom Middleware Configuration
```javascript
// ID token middleware (default)
const idTokenAuth = authManager.authMiddleware({ tokenUse: 'id' });

// Access token middleware
const accessTokenAuth = authManager.authMiddleware({ tokenUse: 'access' });

// Development middleware (skips verification in dev)
const devAuth = authManager.authMiddleware({ 
  tokenUse: 'id', 
  skipVerification: process.env.NODE_ENV === 'development' 
});
```

### Manual Authentication Operations
```javascript
// Signup
const { userSub } = await authManager.signup(email, password);

// Login
const tokens = await authManager.login(email, password);

// Refresh tokens
const newTokens = await authManager.refreshToken(refreshToken);
```

## Troubleshooting

### Common Issues

1. **"CognitoAuthManager configuration validation failed"**
   - Check your environment variables in `.env`
   - Ensure all required fields are set

2. **"Invalid or expired refresh token"**
   - Tokens expire based on Cognito configuration
   - Use the refresh endpoint to get new tokens

3. **"Access denied: No tenant information found"**
   - The JWT doesn't contain `custom:tenantId` claim
   - Configure custom attributes in your Cognito User Pool

4. **401 Unauthorized on protected endpoints**
   - Check the `Authorization` header format: `Bearer <token>`
   - Ensure you're using the correct token type (ID vs Access)

### Debug Mode

Set `NODE_ENV=development` to enable:
- Detailed error logging
- Skip verification on development endpoints
- More verbose console output

## Next Steps

- Configure your AWS Cognito User Pool with custom attributes
- Add custom claims to your JWT tokens
- Implement role-based access control
- Add rate limiting and security headers
- Deploy to your preferred hosting platform

For more information, see the main package documentation.