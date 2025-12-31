#!/bin/bash

# LocalStack Cognito setup script
# This script creates a test Cognito User Pool and App Client for local development

set -e

echo "Setting up Cognito User Pool for local development..."

# Configuration
USER_POOL_NAME="test-user-pool"
APP_CLIENT_NAME="test-app-client"
REGION="us-east-1"

# Create User Pool
echo "Creating User Pool: $USER_POOL_NAME"
USER_POOL_ID=$(awslocal cognito-idp create-user-pool \
  --pool-name "$USER_POOL_NAME" \
  --region "$REGION" \
  --policies '{
    "PasswordPolicy": {
      "MinimumLength": 8,
      "RequireUppercase": false,
      "RequireLowercase": false,
      "RequireNumbers": false,
      "RequireSymbols": false
    }
  }' \
  --auto-verified-attributes email \
  --username-attributes email \
  --verification-message-template '{
    "DefaultEmailOption": "CONFIRM_WITH_CODE"
  }' \
  --query 'UserPool.Id' \
  --output text)

echo "Created User Pool with ID: $USER_POOL_ID"

# Create App Client (without secret)
echo "Creating App Client: $APP_CLIENT_NAME"
APP_CLIENT_ID=$(awslocal cognito-idp create-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-name "$APP_CLIENT_NAME" \
  --region "$REGION" \
  --explicit-auth-flows ADMIN_NO_SRP_AUTH ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --generate-secret \
  --query 'UserPoolClient.ClientId' \
  --output text)

echo "Created App Client with ID: $APP_CLIENT_ID"

# Get App Client Secret
APP_CLIENT_SECRET=$(awslocal cognito-idp describe-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-id "$APP_CLIENT_ID" \
  --region "$REGION" \
  --query 'UserPoolClient.ClientSecret' \
  --output text)

echo "App Client Secret: $APP_CLIENT_SECRET"

# Create App Client without secret for testing
APP_CLIENT_NO_SECRET_ID=$(awslocal cognito-idp create-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-name "$APP_CLIENT_NAME-no-secret" \
  --region "$REGION" \
  --explicit-auth-flows ADMIN_NO_SRP_AUTH ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --query 'UserPoolClient.ClientId' \
  --output text)

echo "Created App Client (no secret) with ID: $APP_CLIENT_NO_SECRET_ID"

# Create test user
echo "Creating test user..."
TEST_EMAIL="test@example.com"
TEST_PASSWORD="TestPassword123!"

awslocal cognito-idp admin-create-user \
  --user-pool-id "$USER_POOL_ID" \
  --username "$TEST_EMAIL" \
  --user-attributes Name=email,Value="$TEST_EMAIL" Name=email_verified,Value=true \
  --temporary-password "$TEST_PASSWORD" \
  --message-action SUPPRESS \
  --region "$REGION"

# Set permanent password
awslocal cognito-idp admin-set-user-password \
  --user-pool-id "$USER_POOL_ID" \
  --username "$TEST_EMAIL" \
  --password "$TEST_PASSWORD" \
  --permanent \
  --region "$REGION"

echo "Created test user: $TEST_EMAIL"

# Save configuration to file
cat > /tmp/localstack-config.json << EOF
{
  "userPoolId": "$USER_POOL_ID",
  "clientId": "$APP_CLIENT_ID",
  "clientSecret": "$APP_CLIENT_SECRET",
  "clientIdNoSecret": "$APP_CLIENT_NO_SECRET_ID",
  "region": "$REGION",
  "testUser": {
    "email": "$TEST_EMAIL",
    "password": "$TEST_PASSWORD"
  },
  "endpoints": {
    "cognito": "http://localhost:4566"
  }
}
EOF

echo "Configuration saved to /tmp/localstack-config.json"
echo "LocalStack Cognito setup completed successfully!"
echo ""
echo "Configuration:"
echo "  User Pool ID: $USER_POOL_ID"
echo "  App Client ID (with secret): $APP_CLIENT_ID"
echo "  App Client Secret: $APP_CLIENT_SECRET"
echo "  App Client ID (no secret): $APP_CLIENT_NO_SECRET_ID"
echo "  Test User: $TEST_EMAIL"
echo "  Test Password: $TEST_PASSWORD"
echo ""
echo "You can now run tests against LocalStack using these credentials."