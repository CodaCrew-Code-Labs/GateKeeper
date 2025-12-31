#!/usr/bin/env node

/**
 * Test script for the example Express application
 * This script demonstrates how to interact with the authentication API
 * 
 * Usage:
 *   node test-endpoints.js
 * 
 * Make sure the example server is running on http://localhost:3000
 */

const http = require('http');

// Configuration
const BASE_URL = 'http://localhost:3000';
const TEST_EMAIL = 'test@example.com';
const TEST_PASSWORD = 'TestPassword123!';

/**
 * Make HTTP request helper
 */
function makeRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed });
        } catch (error) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

/**
 * Add authorization header for protected endpoints
 */
function makeAuthenticatedRequest(method, path, token, data = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed });
        } catch (error) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

/**
 * Test runner
 */
async function runTests() {
  console.log('🧪 Testing @gateway/cognito-auth Example API\n');

  try {
    // Test 1: Health check
    console.log('1️⃣  Testing health check endpoint...');
    const health = await makeRequest('GET', '/');
    console.log(`   Status: ${health.status}`);
    console.log(`   Response: ${JSON.stringify(health.data, null, 2)}\n`);

    // Test 2: Signup (will fail without real Cognito, but shows the API)
    console.log('2️⃣  Testing signup endpoint...');
    const signup = await makeRequest('POST', '/auth/signup', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    });
    console.log(`   Status: ${signup.status}`);
    console.log(`   Response: ${JSON.stringify(signup.data, null, 2)}\n`);

    // Test 3: Login (will fail without real Cognito, but shows the API)
    console.log('3️⃣  Testing login endpoint...');
    const login = await makeRequest('POST', '/auth/login', {
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    });
    console.log(`   Status: ${login.status}`);
    console.log(`   Response: ${JSON.stringify(login.data, null, 2)}\n`);

    // Test 4: Protected endpoint without token
    console.log('4️⃣  Testing protected endpoint without token...');
    const profileNoAuth = await makeRequest('GET', '/profile');
    console.log(`   Status: ${profileNoAuth.status}`);
    console.log(`   Response: ${JSON.stringify(profileNoAuth.data, null, 2)}\n`);

    // Test 5: Protected endpoint with invalid token
    console.log('5️⃣  Testing protected endpoint with invalid token...');
    const profileBadAuth = await makeAuthenticatedRequest('GET', '/profile', 'invalid-token');
    console.log(`   Status: ${profileBadAuth.status}`);
    console.log(`   Response: ${JSON.stringify(profileBadAuth.data, null, 2)}\n`);

    // Test 6: Development endpoint (should work if NODE_ENV=development)
    console.log('6️⃣  Testing development endpoint...');
    const devEndpoint = await makeRequest('GET', '/dev/test');
    console.log(`   Status: ${devEndpoint.status}`);
    console.log(`   Response: ${JSON.stringify(devEndpoint.data, null, 2)}\n`);

    // Test 7: Multi-tenant endpoint
    console.log('7️⃣  Testing multi-tenant endpoint...');
    const tenantEndpoint = await makeRequest('GET', '/tenant/info');
    console.log(`   Status: ${tenantEndpoint.status}`);
    console.log(`   Response: ${JSON.stringify(tenantEndpoint.data, null, 2)}\n`);

    // Test 8: 404 endpoint
    console.log('8️⃣  Testing 404 endpoint...');
    const notFound = await makeRequest('GET', '/nonexistent');
    console.log(`   Status: ${notFound.status}`);
    console.log(`   Response: ${JSON.stringify(notFound.data, null, 2)}\n`);

    console.log('✅ All tests completed!');
    console.log('\n📝 Notes:');
    console.log('   - Authentication endpoints will fail without proper Cognito configuration');
    console.log('   - This is expected behavior for testing the API structure');
    console.log('   - Configure your .env file with real Cognito settings for full functionality');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n💡 Make sure the example server is running:');
    console.log('   cd example && npm start');
  }
}

// Run tests if this script is executed directly
if (require.main === module) {
  runTests();
}

module.exports = { runTests, makeRequest, makeAuthenticatedRequest };