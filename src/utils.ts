// Utility functions for the cognito-auth package
// Requirements: 1.6

import { createHmac } from 'crypto';

/**
 * Compute secret hash for Cognito operations when clientSecret is provided
 * Requirements: 1.6
 *
 * Based on AWS documentation: The secret hash is a Base64-encoded HMAC-SHA256 hash
 * using the client secret as the key and the concatenation of username and client ID as the message.
 *
 * @param username - Username for the operation
 * @param clientId - Cognito app client ID
 * @param clientSecret - Cognito app client secret
 * @returns Base64-encoded HMAC-SHA256 hash
 */
export function computeSecretHash(
  username: string,
  clientId: string,
  clientSecret: string
): string {
  const message = username + clientId;
  // lgtm[js/insufficient-password-hash] This is AWS Cognito's required secret hash format, not password hashing
  const hash = createHmac('sha256', clientSecret).update(message).digest('base64');
  return hash;
}
