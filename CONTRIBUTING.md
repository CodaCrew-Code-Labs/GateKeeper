# Contributing to @gateway/cognito-auth

Thank you for your interest in contributing to @gateway/cognito-auth! We welcome contributions from the community and are grateful for your help in making this package better.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing Guidelines](#testing-guidelines)
- [Code Style](#code-style)
- [Documentation](#documentation)
- [Issue Reporting](#issue-reporting)
- [Security](#security)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@gateway.dev.

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js**: Version 20.0.0 or higher
- **npm**: Version 9.0.0 or higher
- **Git**: For version control
- **Docker**: For LocalStack integration testing (optional)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cognito-auth.git
   cd cognito-auth
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/gateway/cognito-auth.git
   ```

## Development Setup

### Initial Setup

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Build the project**:
   ```bash
   npm run build
   ```

3. **Run tests**:
   ```bash
   npm test
   ```

4. **Start LocalStack (optional)**:
   ```bash
   npm run dev:setup
   ```

5. **Run integration tests**:
   ```bash
   npm run test:localstack
   ```

### Development Scripts

| Script | Description |
|--------|-------------|
| `npm run build` | Build all formats (CommonJS, ESM, TypeScript definitions) |
| `npm run dev` | Start TypeScript compiler in watch mode |
| `npm test` | Run all tests |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run test:localstack` | Run LocalStack integration tests |
| `npm run lint` | Run ESLint |
| `npm run lint:fix` | Fix ESLint issues automatically |
| `npm run format` | Format code with Prettier |
| `npm run format:check` | Check code formatting |
| `npm run dev:setup` | Start LocalStack for local testing |
| `npm run dev:stop` | Stop LocalStack |

### Project Structure

```
src/
├── auth-manager.ts      # Main CognitoAuthManager class
├── middleware.ts        # Express middleware
├── jwt-verification.ts  # JWT verification utilities
├── jwks-cache.ts       # JWKS caching implementation
├── config.ts           # Configuration validation
├── validation.ts       # Input validation utilities
├── utils.ts            # Utility functions
├── errors.ts           # Custom error classes
├── types.ts            # TypeScript type definitions
├── error-handler.ts    # Error handling utilities
├── retry-handler.ts    # Network retry logic
└── index.ts            # Main entry point

tests/
├── *.test.ts           # Unit tests
├── setup.ts            # Test setup
└── localstack.config.ts # LocalStack configuration

example/
├── index.js            # Example Express application
├── package.json        # Example dependencies
└── README.md           # Example documentation

scripts/
├── dev-setup.sh        # LocalStack setup script
└── dev-stop.sh         # LocalStack cleanup script
```

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

1. **Bug Reports**: Help us identify and fix issues
2. **Feature Requests**: Suggest new functionality
3. **Code Contributions**: Implement bug fixes or new features
4. **Documentation**: Improve or add documentation
5. **Tests**: Add or improve test coverage
6. **Examples**: Provide usage examples

### Before You Start

1. **Check existing issues**: Look for existing issues or discussions about your idea
2. **Create an issue**: For significant changes, create an issue to discuss the approach
3. **Small changes**: For small bug fixes or improvements, you can directly create a PR

### Branching Strategy

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Use descriptive branch names**:
   - `feature/add-custom-claims-support`
   - `bugfix/fix-token-refresh-error`
   - `docs/update-api-documentation`
   - `test/add-middleware-tests`

3. **Keep branches focused**: One feature or fix per branch

## Pull Request Process

### Before Submitting

1. **Update your branch** with the latest changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full test suite**:
   ```bash
   npm test
   npm run test:coverage
   npm run test:localstack
   ```

3. **Check code quality**:
   ```bash
   npm run lint
   npm run format:check
   ```

4. **Build the project**:
   ```bash
   npm run build
   ```

### Pull Request Template

When creating a pull request, please include:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Test improvement

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Integration tests pass
- [ ] Code coverage maintained or improved

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] Any dependent changes have been merged and published

## Related Issues
Fixes #(issue number)
```

### Review Process

1. **Automated Checks**: All PRs must pass automated checks (tests, linting, build)
2. **Code Review**: At least one maintainer will review your code
3. **Feedback**: Address any feedback or requested changes
4. **Approval**: Once approved, a maintainer will merge your PR

## Testing Guidelines

### Test Types

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **Property-Based Tests**: Test properties across many inputs
4. **LocalStack Tests**: Test against mock AWS services

### Writing Tests

#### Unit Tests

```typescript
import { describe, it, expect } from 'vitest';
import { validateEmail } from '../src/validation.js';

describe('validateEmail', () => {
  it('should validate correct email addresses', () => {
    expect(validateEmail('user@example.com')).toBe('user@example.com');
  });

  it('should throw for invalid email addresses', () => {
    expect(() => validateEmail('invalid-email')).toThrow();
  });
});
```

#### Property-Based Tests

```typescript
import { fc } from 'fast-check';

describe('Property: Configuration Validation', () => {
  it('should validate all valid configurations', () => {
    fc.assert(fc.property(
      fc.record({
        userPoolId: fc.string().filter(s => s.match(/^[\w-]+_[a-zA-Z0-9]+$/)),
        clientId: fc.string().filter(s => s.match(/^[a-z0-9]+$/)),
        region: fc.string().filter(s => s.match(/^[a-z0-9-]+$/))
      }),
      (config) => {
        expect(() => validateCognitoConfig(config)).not.toThrow();
      }
    ));
  });
});
```

### Test Coverage Requirements

- **Minimum 95% code coverage** for all new code
- **100% coverage** for critical security functions
- **Property-based tests** for core functionality
- **Integration tests** for AWS service interactions

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- auth-manager.test.ts

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run LocalStack integration tests
npm run test:localstack
```

## Code Style

### TypeScript Guidelines

1. **Use strict TypeScript**: Enable all strict mode options
2. **Explicit types**: Prefer explicit type annotations for public APIs
3. **Interface over type**: Use interfaces for object shapes
4. **Readonly when possible**: Use readonly for immutable data

```typescript
// Good
interface CognitoConfig {
  readonly userPoolId: string;
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly region: string;
}

// Avoid
type CognitoConfig = {
  userPoolId: string;
  clientId: string;
  clientSecret?: string;
  region: string;
};
```

### Code Formatting

We use Prettier for code formatting. Configuration is in `.prettierrc`:

```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2
}
```

### ESLint Rules

Key ESLint rules we follow:

- **@typescript-eslint/no-unused-vars**: No unused variables
- **@typescript-eslint/explicit-function-return-type**: Explicit return types for functions
- **@typescript-eslint/no-explicit-any**: Avoid `any` type
- **prefer-const**: Use const for non-reassigned variables

### Naming Conventions

- **Classes**: PascalCase (`CognitoAuthManager`)
- **Functions**: camelCase (`validateEmail`)
- **Constants**: UPPER_SNAKE_CASE (`ENV_VAR_NAMES`)
- **Interfaces**: PascalCase (`CognitoConfig`)
- **Files**: kebab-case (`auth-manager.ts`)

### Comments and Documentation

1. **JSDoc for public APIs**:
   ```typescript
   /**
    * Authenticate user with email and password
    * @param email - User's email address
    * @param password - User's password
    * @returns Promise resolving to authentication tokens
    * @throws {AuthenticationError} When login fails
    */
   public async login(email: string, password: string): Promise<AuthTokens>
   ```

2. **Inline comments for complex logic**:
   ```typescript
   // Compute secret hash using HMAC-SHA256 as per AWS specification
   const hash = createHmac('sha256', clientSecret)
     .update(username + clientId)
     .digest('base64');
   ```

3. **Requirements traceability**:
   ```typescript
   /**
    * Extract Bearer token from Authorization header
    * Requirements: 2.1, 2.3
    */
   ```

## Documentation

### Types of Documentation

1. **API Documentation**: JSDoc comments for all public APIs
2. **README**: Comprehensive usage guide
3. **Examples**: Working code examples
4. **Inline Comments**: Complex logic explanation

### Documentation Standards

1. **Clear and concise**: Write for developers of all skill levels
2. **Code examples**: Include working code examples
3. **Error scenarios**: Document error conditions and handling
4. **Security considerations**: Highlight security implications

### Updating Documentation

When making changes:

1. **Update JSDoc comments** for modified APIs
2. **Update README** if public API changes
3. **Update examples** if usage patterns change
4. **Add CHANGELOG entry** for all changes

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

1. **Clear title**: Descriptive title summarizing the issue
2. **Environment**: Node.js version, package version, OS
3. **Steps to reproduce**: Minimal steps to reproduce the issue
4. **Expected behavior**: What you expected to happen
5. **Actual behavior**: What actually happened
6. **Code sample**: Minimal code that reproduces the issue
7. **Error messages**: Full error messages and stack traces

### Feature Requests

When requesting features:

1. **Use case**: Describe the problem you're trying to solve
2. **Proposed solution**: Your idea for solving it
3. **Alternatives**: Other solutions you've considered
4. **Breaking changes**: Whether this would be a breaking change

### Issue Labels

We use labels to categorize issues:

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements or additions to documentation
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention is needed
- `security`: Security-related issue
- `breaking change`: Would cause breaking changes

## Security

### Security-Related Contributions

For security-related contributions:

1. **Follow security guidelines**: See [SECURITY.md](./SECURITY.md)
2. **Private disclosure**: Report vulnerabilities privately first
3. **Security review**: Security changes require additional review
4. **Testing**: Include security-focused tests

### Security Considerations

When contributing:

1. **Input validation**: Validate all inputs
2. **Error handling**: Don't expose sensitive information
3. **Dependencies**: Keep dependencies updated
4. **Secrets**: Never commit secrets or credentials

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Create release PR
5. Tag release after merge
6. Publish to npm

## Getting Help

### Community Support

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bug reports and feature requests
- **Email**: support@gateway.dev for direct support

### Maintainer Contact

- **Lead Maintainer**: maintainer@gateway.dev
- **Security Issues**: security@gateway.dev
- **General Questions**: support@gateway.dev

## Recognition

### Contributors

We recognize contributors in several ways:

1. **CONTRIBUTORS.md**: List of all contributors
2. **Release notes**: Credit for significant contributions
3. **GitHub**: Contributor statistics and recognition

### Contribution Types

We recognize various types of contributions:

- 💻 Code
- 📖 Documentation
- 🐛 Bug reports
- 💡 Ideas
- 🤔 Answering questions
- ⚠️ Tests
- 🚇 Infrastructure
- 🔍 Reviewed PRs

---

Thank you for contributing to @gateway/cognito-auth! Your contributions help make this package better for everyone.