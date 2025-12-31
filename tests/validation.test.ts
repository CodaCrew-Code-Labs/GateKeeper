import { describe, it, expect } from 'vitest';
import {
  validateEmail,
  validatePassword,
  validateUsername,
  validateVerificationCode,
  validateJWTToken,
  validateAuthorizationHeader,
  sanitizeForLogging,
} from '../src/validation.js';
import { ValidationError } from '../src/errors.js';

describe('Input Validation and Security', () => {
  describe('Email Validation', () => {
    it('should validate correct emails', () => {
      expect(validateEmail('user@example.com')).toBe('user@example.com');
      expect(validateEmail('test.email@domain.co.uk')).toBe('test.email@domain.co.uk');
    });

    it('should reject invalid emails', () => {
      expect(() => validateEmail('')).toThrow(ValidationError);
      expect(() => validateEmail('invalid-email')).toThrow(ValidationError);
      expect(() => validateEmail('user@')).toThrow(ValidationError);
      expect(() => validateEmail('@example.com')).toThrow(ValidationError);
    });

    it('should reject malicious inputs', () => {
      expect(() => validateEmail('<script>alert(1)</script>')).toThrow(ValidationError);
      expect(() => validateEmail('user\x00@example.com')).toThrow(ValidationError);
    });
  });

  describe('Password Validation', () => {
    it('should validate correct passwords', () => {
      expect(validatePassword('password123')).toBe('password123');
      expect(validatePassword('MySecure@Pass123')).toBe('MySecure@Pass123');
    });

    it('should reject invalid passwords', () => {
      expect(() => validatePassword('')).toThrow(ValidationError);
      expect(() => validatePassword('short')).toThrow(ValidationError);
      expect(() => validatePassword('pass\x00word')).toThrow(ValidationError);
    });
  });

  describe('Username Validation', () => {
    it('should validate correct usernames', () => {
      expect(validateUsername('user123')).toBe('user123');
      expect(validateUsername('user@example.com')).toBe('user@example.com');
    });

    it('should reject invalid usernames', () => {
      expect(() => validateUsername('')).toThrow(ValidationError);
      expect(() => validateUsername('   ')).toThrow(ValidationError);
      expect(() => validateUsername('user\x00name')).toThrow(ValidationError);
    });
  });

  describe('Verification Code Validation', () => {
    it('should validate correct codes', () => {
      expect(validateVerificationCode('123456')).toBe('123456');
      expect(validateVerificationCode('ABC123')).toBe('ABC123');
    });

    it('should reject invalid codes', () => {
      expect(() => validateVerificationCode('')).toThrow(ValidationError);
      expect(() => validateVerificationCode('123-456')).toThrow(ValidationError);
      expect(() => validateVerificationCode('123 456')).toThrow(ValidationError);
    });
  });

  describe('JWT Token Validation', () => {
    it('should validate correct JWT tokens', () => {
      const validJWT =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
      expect(validateJWTToken(validJWT)).toBe(validJWT);
    });

    it('should reject invalid JWT tokens', () => {
      expect(() => validateJWTToken('')).toThrow(ValidationError);
      expect(() => validateJWTToken('invalid.token')).toThrow(ValidationError);
      expect(() => validateJWTToken('invalid-token-format')).toThrow(ValidationError);
    });
  });

  describe('Authorization Header Validation', () => {
    it('should validate correct Bearer tokens', () => {
      expect(validateAuthorizationHeader('Bearer valid-token')).toBe('Bearer valid-token');
    });

    it('should return null for invalid formats', () => {
      expect(validateAuthorizationHeader('Basic dXNlcjpwYXNz')).toBeNull();
      expect(validateAuthorizationHeader('Bearer')).toBeNull();
      expect(validateAuthorizationHeader('Bearer ')).toBeNull();
      expect(validateAuthorizationHeader('')).toBeNull();
    });

    it('should throw for malicious inputs', () => {
      expect(() => validateAuthorizationHeader('Bearer token\x00')).toThrow(ValidationError);
      expect(() => validateAuthorizationHeader('\x01\x02\x03')).toThrow(ValidationError);
    });
  });

  describe('Logging Sanitization', () => {
    it('should redact sensitive fields', () => {
      const data = {
        password: 'secret123',
        token: 'jwt-token-here',
        normalField: 'safe-data',
      };

      const sanitized = sanitizeForLogging(data);
      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.token).toBe('[REDACTED]');
      expect(sanitized.normalField).toBe('safe-data');
    });
  });

  describe('Security Tests', () => {
    const maliciousInputs = [
      '<script>alert(1)</script>',
      'javascript:alert(1)',
      '; DROP TABLE users; --',
      '../../etc/passwd',
      'admin\x00',
      'user\r\nadmin',
    ];

    it('should reject SQL injection attempts', () => {
      maliciousInputs.forEach(input => {
        expect(() => validateEmail(input)).toThrow(ValidationError);
      });
    });

    it('should handle type confusion attacks', () => {
      const nonStringInputs = [null, undefined, 123, true, [], {}];

      nonStringInputs.forEach(input => {
        expect(() => validateEmail(input as unknown)).toThrow(ValidationError);
        expect(() => validatePassword(input as unknown)).toThrow(ValidationError);
        expect(() => validateUsername(input as unknown)).toThrow(ValidationError);
      });
    });
  });
});
