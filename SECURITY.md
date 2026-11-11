# Security Policy

## Overview

`lh-totp-core` is an enterprise-grade Two-Factor Authentication (2FA) engine, RFC 6238 TOTP & RFC 4226 HOTP generator,
single-use backup code manager, and multi-factor authentication (MFA) posture auditor developed by **Logihertz Systems (OPC) Private Limited**.
Engineered with a strict clean-room design and zero external runtime dependencies, `lh-totp-core` operates with complete cryptographic
determinism, constant-time verification safety, and token replay prevention.

---

## Supported Versions

Only the latest active release of `lh-totp-core` receives security updates and vulnerability patches.

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability, cryptographic flaw, timing side-channel, replay bypass,
or denial-of-service issue in `lh-totp-core`, please report it responsibly through our coordinated security response channel.
**Do not create a public GitHub issue for security vulnerabilities.**

### Vulnerability Reporting Process

1. **Email Details**: Send an advisory email to:
   - **security@logihertz.com**
   - **ops@logihertz.com**
2. **Include Key Information**:
   - Affected component (`Base32`, `HotpEngine`, `TotpEngine`, `BackupCodeManager`, `TotpAuditor`, CLI)
   - Specific version of `lh-totp-core`
   - Detailed description of the vulnerability and attack vector
   - Minimal reproduction script, proof-of-concept OTP payload, or policy configuration manifest
3. **Response Timeline**:
   - **Acknowledgment**: Within **48 hours** of receiving your report.
   - **Triage & Status**: Within **3 business days** with preliminary assessment and reproduction verification.
   - **Remediation & Patch**: We aim to release a verified patch within **5 business days** for high or critical severity issues.

---

## Security Engineering Standards

`lh-totp-core` enforces rigorous internal engineering controls:
- **Zero Third-Party Runtime Dependencies**: Zero `vendor/` supply chain footprint in production.
- **Timing Side-Channel Immunity**: All token and backup code comparisons strictly employ constant-time evaluation via `hash_equals()`. Look-ahead and drift windows evaluate all candidate steps without early termination.
- **Cryptographic Randomness (CSPRNG)**: All secret generation, salt generation, and recovery codes originate strictly from `random_bytes()` and `random_int()`.
- **Replay Protection**: Integrated token cache guarantees that any single OTP cannot be reused within its valid time window.
- **Backup Code Protection**: Recovery codes are hashed at rest using PBKDF2-HMAC-SHA256 (100,000 iterations) with cryptographic salts and marked permanently spent upon consumption.
