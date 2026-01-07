// Example Express application demonstrating @gateway/cognito-auth usage
// This example shows complete integration with authentication flows and middleware

const express = require('express');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import the authentication package
// In a real application, this would be: const { CognitoAuthManager } = require('@gateway/cognito-auth');
// For this example, we'll use the local build
const { CognitoAuthManager } = require('../dist/cjs/index.js');

const app = express();
const port = process.env.PORT || 3000;

// Middleware for parsing JSON bodies
app.use(express.json());

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Initialize the Cognito Auth Manager
let authManager;
try {
  authManager = new CognitoAuthManager({
    userPoolId: process.env.COGNITO_USER_POOL_ID,
    clientId: process.env.COGNITO_CLIENT_ID,
    clientSecret: process.env.COGNITO_CLIENT_SECRET, // Optional for public clients
    region: process.env.AWS_REGION || 'us-east-1',
    domain: process.env.COGNITO_DOMAIN,
    redirectUri: process.env.COGNITO_REDIRECT_URI
  });
  console.log('✅ CognitoAuthManager initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize CognitoAuthManager:', error.message);
  process.exit(1);
}

// Create authentication middleware instances
const authMiddleware = authManager.authMiddleware({ tokenUse: 'id' });
const accessTokenMiddleware = authManager.authMiddleware({ tokenUse: 'access' });
const devMiddleware = authManager.authMiddleware({ 
  tokenUse: 'id', 
  skipVerification: process.env.NODE_ENV === 'development' 
});

// Public routes (no authentication required)

/**
 * Health check endpoint
 */
app.get('/', (req, res) => {
  res.json({ 
    message: 'AWS Cognito Authentication Example API',
    version: '1.0.0',
    endpoints: {
      public: [
        'GET /',
        'POST /auth/signup',
        'POST /auth/confirm',
        'POST /auth/login',
        'POST /auth/refresh',
        'GET /auth/google/url',
        'POST /auth/google/callback'
      ],
      protected: [
        'GET /profile',
        'GET /admin/users',
        'GET /tenant/info'
      ]
    }
  });
});

/**
 * Get Google OAuth Login URL
 */
app.get('/auth/google/url', (req, res) => {
  try {
    const url = authManager.getGoogleAuthUrl();
    res.json({ url });
  } catch (error) {
    console.error('Google Auth URL error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Google OAuth Callback
 * Exchanges the code for tokens
 */
app.post('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    const tokens = await authManager.exchangeCodeForTokens(code);
    
    res.json({
      message: 'Google login successful',
      tokens: {
        idToken: tokens.idToken,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      }
    });
  } catch (error) {
    console.error('Google callback error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Google login failed'
    });
  }
});

/**
 * User signup endpoint
 * Demonstrates the signup flow with email and password
 */
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required'
      });
    }

    const result = await authManager.signup(email, password);
    
    res.status(201).json({
      message: 'User created successfully. Please check your email for verification code.',
      userSub: result.userSub
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Signup failed'
    });
  }
});

/**
 * User signup with username endpoint
 * Demonstrates the signup flow with username, email and password
 */
app.post('/auth/signup-username', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email and password are required'
      });
    }

    // Call the new signupWithUsername method
    const result = await authManager.signupWithUsername(username, email, password);
    
    res.status(201).json({
      message: 'User created successfully with username. Please check your email for verification code.',
      userSub: result.userSub
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Signup failed'
    });
  }
});

/**
 * Signup confirmation endpoint
 * Demonstrates confirming user signup with verification code
 */
app.post('/auth/confirm', async (req, res) => {
  try {
    const { username, code } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({
        error: 'Username and verification code are required'
      });
    }

    await authManager.confirmSignup(username, code);
    
    res.json({
      message: 'Account confirmed successfully. You can now log in.'
    });
  } catch (error) {
    console.error('Confirmation error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Confirmation failed'
    });
  }
});

/**
 * User login endpoint
 * Demonstrates the login flow returning JWT tokens
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required'
      });
    }

    const tokens = await authManager.login(email, password);
    
    res.json({
      message: 'Login successful',
      tokens: {
        idToken: tokens.idToken,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Login failed'
    });
  }
});

/**
 * Token refresh endpoint
 * Demonstrates refreshing expired tokens
 */
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token is required'
      });
    }

    const tokens = await authManager.refreshToken(refreshToken);
    
    res.json({
      message: 'Tokens refreshed successfully',
      tokens: {
        idToken: tokens.idToken,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      }
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(error.statusCode || 500).json({
      error: error.message || 'Token refresh failed'
    });
  }
});

// Protected routes (authentication required)

/**
 * User profile endpoint
 * Demonstrates basic JWT middleware usage with ID tokens
 */
app.get('/profile', authMiddleware, (req, res) => {
  res.json({
    message: 'User profile retrieved successfully',
    user: {
      sub: req.user.sub,
      email: req.user.email,
      customClaims: req.user.customClaims
    }
  });
});

/**
 * Admin endpoint
 * Demonstrates access token middleware usage
 */
app.get('/admin/users', accessTokenMiddleware, (req, res) => {
  // In a real application, you would check for admin permissions here
  res.json({
    message: 'Admin endpoint accessed successfully',
    user: {
      sub: req.user.sub,
      email: req.user.email,
      customClaims: req.user.customClaims
    },
    data: {
      totalUsers: 42,
      activeUsers: 38
    }
  });
});

/**
 * Multi-tenant endpoint
 * Demonstrates custom claims extraction for tenant isolation
 */
app.get('/tenant/info', authMiddleware, (req, res) => {
  const tenantId = req.user.customClaims?.['custom:tenantId'];
  
  if (!tenantId) {
    return res.status(403).json({
      error: 'Access denied: No tenant information found'
    });
  }

  res.json({
    message: 'Tenant information retrieved successfully',
    tenant: {
      id: tenantId,
      name: `Tenant ${tenantId}`,
      plan: req.user.customClaims?.['custom:plan'] || 'basic'
    },
    user: {
      sub: req.user.sub,
      email: req.user.email,
      role: req.user.customClaims?.['custom:role'] || 'user'
    }
  });
});

/**
 * Development endpoint with skip verification
 * Demonstrates development-mode middleware usage
 */
app.get('/dev/test', devMiddleware, (req, res) => {
  res.json({
    message: 'Development endpoint accessed',
    note: 'This endpoint skips JWT verification in development mode',
    user: req.user || { message: 'No user data (verification skipped)' },
    environment: process.env.NODE_ENV
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found'
  });
});

// Start the server
app.listen(port, () => {
  console.log(`🚀 Example app listening at http://localhost:${port}`);
  console.log(`📚 API documentation available at http://localhost:${port}/`);
  
  // Display configuration status
  console.log('\n📋 Configuration Status:');
  console.log(`   User Pool ID: ${process.env.COGNITO_USER_POOL_ID ? '✅ Set' : '❌ Missing'}`);
  console.log(`   Client ID: ${process.env.COGNITO_CLIENT_ID ? '✅ Set' : '❌ Missing'}`);
  console.log(`   Client Secret: ${process.env.COGNITO_CLIENT_SECRET ? '✅ Set' : '⚠️  Not set (OK for public clients)'}`);
  console.log(`   AWS Region: ${process.env.AWS_REGION || 'us-east-1'}`);
  console.log(`   Cognito Domain: ${process.env.COGNITO_DOMAIN ? '✅ Set' : '❌ Missing'}`);
  console.log(`   Redirect URI: ${process.env.COGNITO_REDIRECT_URI ? '✅ Set' : '❌ Missing'}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  
  if (!process.env.COGNITO_USER_POOL_ID || !process.env.COGNITO_CLIENT_ID) {
    console.log('\n⚠️  Warning: Missing required environment variables. Copy .env.example to .env and configure your Cognito settings.');
  }
});