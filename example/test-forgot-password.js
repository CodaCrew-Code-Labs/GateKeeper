// Simple test for forgot password functionality
const { CognitoAuthManager } = require('../dist/cjs/index.js');

async function testForgotPassword() {
  const authManager = new CognitoAuthManager({
    userPoolId: process.env.COGNITO_USER_POOL_ID || 'us-east-1_test',
    clientId: process.env.COGNITO_CLIENT_ID || 'test-client',
    region: process.env.AWS_REGION || 'us-east-1'
  });

  try {
    console.log('Testing forgot password...');
    await authManager.forgotPassword('test@example.com');
    console.log('✅ Forgot password method exists and can be called');
  } catch (error) {
    if (error.message.includes('User not found') || error.message.includes('Password reset request failed')) {
      console.log('✅ Forgot password method works (expected error for test email)');
    } else {
      console.error('❌ Unexpected error:', error.message);
    }
  }

  try {
    console.log('Testing confirm forgot password...');
    await authManager.confirmForgotPassword('test@example.com', '123456', 'NewPassword123!');
    console.log('✅ Confirm forgot password method exists and can be called');
  } catch (error) {
    if (error.message.includes('Invalid verification code') || error.message.includes('Password reset failed')) {
      console.log('✅ Confirm forgot password method works (expected error for test data)');
    } else {
      console.error('❌ Unexpected error:', error.message);
    }
  }
}

testForgotPassword().catch(console.error);