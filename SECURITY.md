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

CipherLink implements Signal Protocol-based E2EE with v3 production hardening. For full details, see:

- [Security Model](docs/SECURITY_MODEL.md) — architecture, protocol flow, key storage
- [Threat Model](docs/THREAT_MODEL.md) — adversary model, what is/isn't protected
- [Crypto Design](docs/CRYPTO_LIMITS.md) — full feature status, cryptographic primitives
- [v2 Architecture](docs/SECURITY_ARCHITECTURE_V2.md) — v2 threat model, attack surface, upgrade plan
- [Audit Pack](docs/audit/) — threat model, attack surface review, security claims mapping

## Current Limitations

This project is a v3 production-hardened prototype. An independent security audit is recommended before high-risk production use. Known limitations:

- PQ KEM uses a placeholder (X25519 in Kyber wire format) — not real post-quantum security until native ML-KEM-768 is available
- Server authentication is public-key claim only — no challenge-response proof
- TLS is enforced in production mode (`wss://`); `ws://` is permitted only in `NODE_ENV=development`
- No server-side integration tests exist
- Multi-device support is designed but not yet implemented ([design doc](docs/design/MULTI_DEVICE.md))
- Cover traffic scheduler is standalone — not integrated into the transport layer
- Deniable authentication is designed but not yet coded

See [FEATURE_STATUS.md](docs/audit/FEATURE_STATUS.md) for the complete feature status table.

## Acknowledgments

We appreciate responsible disclosure and will acknowledge reporters (with permission) in release notes.
