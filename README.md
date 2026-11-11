# lh-totp-core

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-totp-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-totp-core/actions/workflows/ci.yml)
[![PHP 8.2+](https://img.shields.io/badge/php-8.2+-8892BF.svg)](https://www.php.net/)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0-success.svg)](composer.json)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS%20SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise-grade, zero-dependency PHP 8.2+ RFC 6238 TOTP & RFC 4226 HOTP Two-Factor Authentication (2FA) Engine, Backup Code Manager, and 10-Rule MFA Posture Auditor developed by **Logihertz Systems (OPC) Private Limited**.

---

## Architectural Highlights

- **100% Zero External Runtime Dependencies**: Operates exclusively upon native PHP 8.2+ core language features and standard system extensions (`ext-hash`, `ext-json`, `ext-spl`, `random_bytes()`, `hash_hmac()`, `hash_equals()`). Zero third-party `vendor/` supply chain footprint.
- **RFC 4226 HOTP Engine**: Strict clean-room implementation of HMAC-Based One-Time Password generation supporting SHA1, SHA256, and SHA512 with 31-bit dynamic truncation and constant-time look-ahead window verification.
- **RFC 6238 TOTP Engine**: Time-Based One-Time Password generation and verification across configurable time steps ($T_x$) with constant-time drift evaluation ($\pm 1$ or $\pm 2$ windows).
- **Token Replay Protection**: Built-in state cache preventing token replay and reuse within the validity window.
- **CSPRNG Backup Code Manager**: Single-use recovery code generator and PBKDF2-HMAC-SHA256 (100,000 iterations) storage-at-rest verifier with state invalidation upon consumption.
- **Key URI Provisioning**: RFC-compliant `otpauth://totp/` URI generator adhering to Google Authenticator specifications.
- **10-Rule MFA Posture Auditor**: Audits MFA policy configurations against deterministic rules `LH-TOTP-001` through `LH-TOTP-010`.
- **Multi-Format Enterprise Exporters**: Colored ANSI terminal tables, canonical JSON, and OASIS SARIF v2.1.0 schemas.

---

## Core Detection Rules

| Rule ID | Severity | CWE | Weight | Description |
|:---|:---:|:---:|:---:|:---|
| `LH-TOTP-001` | `CRITICAL` | `CWE-326` | 25 | Shared secret bit length `< 128` bits (`secret_bits < 128`) or low Shannon entropy seed |
| `LH-TOTP-002` | `CRITICAL` | `CWE-294` | 25 | OTP replay protection disabled (`replay_protection_enabled: false`), allowing token reuse |
| `LH-TOTP-003` | `HIGH` | `CWE-307` | 10 | Excessive clock-drift verification window (`window_steps > 2`), widening vulnerability window |
| `LH-TOTP-004` | `HIGH` | `CWE-307` | 10 | Missing or weak MFA verification lockout (`max_failed_attempts > 5` or `lockout_duration_seconds < 300`) |
| `LH-TOTP-005` | `HIGH` | `CWE-330` | 10 | Excessive time-step period (`period_seconds > 60`) or weak code length (`digits < 6`) |
| `LH-TOTP-006` | `MEDIUM` | `CWE-328` | 4 | Legacy `SHA1` digest algorithm configured (`algorithm: "SHA1"`) instead of `SHA256` or `SHA512` |
| `LH-TOTP-007` | `CRITICAL` | `CWE-312` | 25 | Plaintext TOTP secret storage at rest (`encrypt_secret_at_rest: false`) or unhashed backup codes |
| `LH-TOTP-008` | `HIGH` | `CWE-208` | 10 | Non-constant-time OTP comparison (`constant_time_verification: false`), exposing timing side-channels |
| `LH-TOTP-009` | `MEDIUM` | `CWE-319` | 4 | Insecure `otpauth://` provisioning hygiene (`require_tls_enrollment: false`, missing `issuer`, or logging seeds) |
| `LH-TOTP-010` | `LOW` | `CWE-755` | 1 | Excessive recovery code count (`backup_code_count > 10`) or insufficient backup code entropy (`backup_code_bits < 64`) |

---

## Mathematical Formulations

### 1. RFC 4226 HOTP Calculation

Given a shared secret $K$, moving counter $C$, and code length $d \in \{6, 7, 8\}$:

$$\text{HOTP}(K, C) = \text{Truncate}(\text{HMAC-SHA-}\alpha(K, C)) \bmod 10^d$$

The counter $C$ is serialized as an 8-byte big-endian unsigned integer. Dynamic Truncation extracts a 31-bit integer $P$ from the HMAC digest $HS$:

$$o = \text{ord}(HS[\text{len}(HS) - 1]) \ \& \ \text{0x0F}$$

$$P = ((HS[o] \ \& \ \text{0x7F}) \ll 24) \mid ((HS[o+1] \ \& \ \text{0xFF}) \ll 16) \mid ((HS[o+2] \ \& \ \text{0xFF}) \ll 8) \mid (HS[o+3] \ \& \ \text{0xFF})$$

$$\text{OTP} = P \bmod 10^d$$

### 2. RFC 6238 TOTP Time-Step Discretization

The continuous Unix timestamp $t$ is discretized into integer time steps $T$ using period $T_x$ (default 30 seconds) and epoch $T_0 = 0$:

$$T = \left\lfloor \frac{t - T_0}{T_x} \right\rfloor$$

$$\text{TOTP}(K, t) = \text{HOTP}(K, T)$$

Verification evaluates candidate steps $T + i$ for $i \in [-w, +w]$ using constant-time `hash_equals()` across all iterations.

### 3. Shannon Entropy of Secret Seeds

Given raw byte sequence $X = (x_1, \dots, x_N)$ with byte frequency distribution $p(x_i)$:

$$H(X) = - \sum_{i=0}^{255} p(x_i) \log_2 p(x_i) \quad [\text{bits/byte}]$$

High-entropy cryptographic seeds achieve $H(X) \ge 3.5$ bits/byte.

### 4. Logihertz Security Posture Score ($S_{\text{posture}}$)

$$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

---

## Installation

### Prerequisites

- **PHP 8.2 or higher**
- Required standard extensions: `ext-hash`, `ext-json`, `ext-spl`

### Direct Execution

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-totp-core.git
cd lh-totp-core

# Verify permissions
chmod +x bin/lh-totp

# Verify version
./bin/lh-totp --version
```

### Composer Integration

```bash
composer require logihertzsystems/lh-totp-core
```

---

## CLI Usage

### 1. Auditing MFA Policy Configuration

```bash
# Scan MFA policy configuration with ANSI terminal table
./bin/lh-totp scan fixtures/hardened_mfa_policy.json

# Export scan results to OASIS SARIF v2.1.0
./bin/lh-totp scan fixtures/hardened_mfa_policy.json --format sarif --output report.sarif

# Export scan results to canonical JSON
./bin/lh-totp scan fixtures/vulnerable_mfa_policy.json --format json
```

### 2. Generating & Verifying TOTP Codes

```bash
# Generate a TOTP code using Base32 secret (defaults to SHA256, 6 digits, 30s)
./bin/lh-totp generate --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

# Verify a user-submitted code in constant time
./bin/lh-totp verify --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --code 123456
```

### 3. Provisioning URI & Backup Codes

```bash
# Build an otpauth:// provisioning URI for authenticator enrollment
./bin/lh-totp provision --issuer "Logihertz Systems" --account "ops@logihertz.com"

# Generate cryptographically secure single-use backup recovery codes
./bin/lh-totp backup-codes --count 8
```

---

## Exit Code Semantics

The CLI enforces deterministic UNIX process exit codes:

| Exit Code | Meaning | Condition |
|:---:|:---|:---|
| `0` | **Success / Valid** | Audit clean (`total_findings === 0`), OTP verified, or command succeeded |
| `1` | **Policy Findings / Invalid OTP** | Security violations found (`total_findings > 0`) or OTP verification failed |
| `2` | **Usage / Error** | Invalid CLI arguments, missing file, or unparseable input |

---

## Running Tests

Execute the zero-dependency test suite (85+ assertions covering RFC test vectors):

```bash
php tests/run_tests.php
```

To run syntax linting across all repository files:

```bash
find src bin tests -type f -exec php -l {} +
```

---

## Enterprise Governance & Community

`lh-totp-core` is an open-source product developed by:

- **Organization**: Logihertz Systems (OPC) Private Limited (`logihertzsystems`)
- **Website**: [https://logihertz.com/](https://logihertz.com/)
- **Contact & Support**: [ops@logihertz.com](mailto:ops@logihertz.com) | [security@logihertz.com](mailto:security@logihertz.com)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** (`ops@logihertz.com`)
- **License**: Apache License 2.0 (SPDX-License-Identifier: `Apache-2.0`). See [LICENSE](LICENSE) and [NOTICE](NOTICE) for complete legal terms.
- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) for architectural mandates and verification standards.
- **Changelog**: Release history and version updates are tracked in [CHANGELOG.md](CHANGELOG.md).
- **Code of Conduct**: Community standards are defined in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security Policy**: Vulnerability reporting protocols are documented in [SECURITY.md](SECURITY.md).
