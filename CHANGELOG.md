# Changelog

All notable changes to **lh-totp-core** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-11

Initial clean-room release of **lh-totp-core**, an enterprise-grade, zero-dependency PHP 8.2+ RFC 6238 TOTP & RFC 4226 HOTP Two-Factor Authentication Engine, Backup Code Manager, and 10-Rule MFA Posture Auditor developed by **Logihertz Systems (OPC) Private Limited**.

### Added

- **Zero-Dependency PSR-4 Autoloader** (`Logihertz\TotpCore\Autoloader`):
  - Lightweight, deterministic autoloader for the `Logihertz\TotpCore\` namespace operating without external Composer runtime dependencies.

- **RFC 4648 Base32 Engine & Entropy Analyzer** (`Logihertz\TotpCore\Base32`):
  - Constant-time RFC 4648 Base32 encoding and decoding with optional padding support.
  - CSPRNG shared secret generator (`generateSecret`) supporting 128-bit to 512-bit seeds via `random_bytes()`.
  - Bit entropy calculation and Shannon entropy analyzer measuring bits of randomness per byte.

- **RFC 4226 HOTP Engine** (`Logihertz\TotpCore\HotpEngine`):
  - RFC 4226 Section 5 HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 one-time password generation.
  - Section 5.4 31-bit Dynamic Truncation with zero-padded code formatting for 6, 7, and 8 digits.
  - Constant-time verification across configurable counter look-ahead windows using `hash_equals()`.
  - Validated against official RFC 4226 Appendix D test vectors across counters $C = 0 \dots 9$.

- **RFC 6238 TOTP Engine & Replay Cache** (`Logihertz\TotpCore\TotpEngine`):
  - RFC 6238 Time-Based One-Time Password generation supporting configurable time periods ($T_x$) and hash digests (SHA1, SHA256, SHA512).
  - Validated against official RFC 6238 Appendix B test vectors across timestamps `59`, `1111111109`, `1111111111`, `1234567890`, `2000000000`, `20000000000`.
  - Constant-time drift window evaluation ($\pm 1$ or $\pm 2$ steps) avoiding timing side-channel leaks.
  - Built-in token replay cache preventing duplicate verification of consumed tokens within their validity windows.
  - Standard Key Uri Format builder (`otpauth://totp/...`) adhering to Google Authenticator specifications.

- **CSPRNG Backup Code Manager** (`Logihertz\TotpCore\BackupCodeManager`):
  - Cryptographically secure single-use recovery code generator using unambiguous character alphabets (`random_int()`).
  - Secure storage-at-rest hashing utilizing PBKDF2-HMAC-SHA256 (100,000 iterations) with cryptographic salts.
  - Constant-time verification with automatic state invalidation upon code consumption.

- **10-Rule MFA Posture Auditor** (`Logihertz\TotpCore\TotpAuditor`):
  - Deterministic evaluation of MFA policy manifests across 10 security rules:
    - `LH-TOTP-001` (CRITICAL, CWE-326): Shared secret bit length $< 128$ bits or low Shannon entropy seed.
    - `LH-TOTP-002` (CRITICAL, CWE-294): OTP replay protection disabled, allowing token reuse within time window.
    - `LH-TOTP-003` (HIGH, CWE-307): Excessive clock-drift verification window ($> 2$ steps).
    - `LH-TOTP-004` (HIGH, CWE-307): Missing or weak MFA verification lockout ($> 5$ attempts or $< 300\text{ s}$ duration).
    - `LH-TOTP-005` (HIGH, CWE-330): Excessive time-step period ($> 60\text{ s}$) or weak code length ($< 6$ digits).
    - `LH-TOTP-006` (MEDIUM, CWE-328): Legacy SHA1 digest algorithm configured instead of SHA256 or SHA512.
    - `LH-TOTP-007` (CRITICAL, CWE-312): Plaintext secret storage at rest or unhashed backup recovery codes.
    - `LH-TOTP-008` (HIGH, CWE-208): Non-constant-time OTP comparison exposing timing side-channels.
    - `LH-TOTP-009` (MEDIUM, CWE-319): Insecure `otpauth://` provisioning hygiene (missing TLS or logging seeds).
    - `LH-TOTP-010` (LOW, CWE-755): Excessive recovery code count ($> 10$) or insufficient backup code entropy ($< 64$ bits).
  - Mathematical Logihertz Security Posture Score ($S_{\text{posture}} \in [0, 100]$):
    $$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

- **Multi-Format Enterprise Exporters** (`Logihertz\TotpCore\Exporters`):
  - Colored ANSI terminal summary table with posture score banner (`--format table`).
  - Canonical JSON report exporter (`--format json`).
  - OASIS SARIF v2.1.0 schema exporter (`--format sarif`) with driver rule definitions and MITRE CWE references.

- **Standalone CLI Executable** (`bin/lh-totp`):
  - Subcommands: `scan`, `generate`, `verify`, `provision`, `backup-codes`, `--version`, and `--help`.
  - Deterministic UNIX process exit codes:
    - `0`: Success / Valid OTP / Clean scan.
    - `1`: Policy violation / Invalid OTP / Verification failure.
    - `2`: CLI usage errors, unreadable files, or parse errors.

- **Deterministic Verification Test Suite** (`tests/run_tests.php`):
  - 85+ zero-dependency assertions covering Base32, RFC 4226 vectors, RFC 6238 vectors, replay caching, backup codes, posture scoring, and CLI execution.
  - Verified across PHP 8.2, 8.3, and 8.4 in GitHub Actions CI.

- **Governance & Legal Documentation**:
  - Full Apache License 2.0 (`LICENSE`).
  - Enterprise attribution and legal reservation notice (`NOTICE`).
  - Coordinated vulnerability disclosure policy (`SECURITY.md`).
  - Developer contribution guidelines (`CONTRIBUTING.md`).
  - Contributor Covenant v2.1 code of conduct (`CODE_OF_CONDUCT.md`).
  - Package manifest (`composer.json`).
  - Enterprise documentation with mathematical specifications and detection tables (`README.md`).

[0.1.0]: https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-totp-core/releases/tag/v0.1.0
