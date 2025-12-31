// Basic test to verify the testing setup is working
import { describe, it, expect } from 'vitest';

describe('Project Setup', () => {
  it('should have a working test environment', () => {
    expect(true).toBe(true);
  });

  it('should be able to import Node.js modules', async () => {
    const crypto = await import('crypto');
    expect(crypto).toBeDefined();
  });
});
