# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in CipherLink, **please do NOT open a public GitHub Issue.**

Instead, report it responsibly:

1. **Email:** Send a detailed report to the project maintainer via the contact information in the repository profile.
2. **GitHub Security Advisories:** Use [GitHub's private vulnerability reporting](https://github.com/BEKO2210/cipherlink/security/advisories/new) to create a draft advisory.

### What to Include

- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The affected component(s) and version(s)
- The potential impact

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity; critical issues targeted within 14 days

### Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Remote key extraction, plaintext recovery, authentication bypass |
| **High** | Replay attacks bypassing protections, session hijacking, denial of service |
| **Medium** | Information disclosure (metadata leaks), weak defaults |
| **Low** | Documentation gaps, non-exploitable code quality issues |

## Security Architecture

CipherLink implements Signal Protocol-based E2EE. For full details, see:

- [Security Model](docs/SECURITY_MODEL.md) — architecture, protocol flow, key storage
- [Threat Model](docs/THREAT_MODEL.md) — adversary model, what is/isn't protected
- [Crypto Design](docs/CRYPTO_LIMITS.md) — full feature status, cryptographic primitives
- [Audit Pack](docs/audit/) — threat model, attack surface review, security claims mapping

## Current Limitations

This project is an advanced prototype, not a production-hardened system. Known limitations:

- PQ KEM uses a placeholder (X25519 in Kyber wire format) — not real post-quantum security
- Server authentication is public-key claim only — no challenge-response proof
- No TLS enforcement in the relay server — must be configured at deployment
- No server-side tests exist
- TreeKEM group protocol has no integration tests
- Cover traffic scheduler is standalone — not integrated into the transport layer

See [FEATURE_STATUS.md](docs/audit/FEATURE_STATUS.md) for the complete feature status table.

## Acknowledgments

We appreciate responsible disclosure and will acknowledge reporters (with permission) in release notes.
