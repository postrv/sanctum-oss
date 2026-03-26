# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Current |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of:

1. **GitHub Private Advisory**: [Create a private advisory](https://github.com/arbiter-security/sanctum/security/advisories/new) on this repository.
2. **Email**: security@sanctum.dev (PGP key available at sanctum.dev/.well-known/security.txt)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - Critical: patch within 72 hours
  - High: patch within 7 days
  - Medium/Low: next scheduled release

### Disclosure policy

We follow coordinated disclosure. We will:
1. Confirm the vulnerability and determine its scope
2. Develop and test a fix
3. Release the fix and publish a security advisory
4. Credit the reporter (unless they prefer anonymity)

We ask that you give us reasonable time to address the issue before public disclosure.

## Security considerations

Sanctum is a security tool with elevated filesystem access. We take its own security extremely seriously:

- **No unsafe code** in the entire codebase
- **All dependencies audited** and documented in `docs/DEPENDENCY_AUDIT.md`
- **Fuzz testing** on all input-parsing code
- **Property-based testing** with 10,000+ cases on security-critical modules
- **Formal verification** via Kani bounded model checking on core algorithms
- **Sigstore attestation** on all release binaries
- **Reproducible builds** verified in CI
