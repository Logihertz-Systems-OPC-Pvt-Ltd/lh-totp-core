# Contributing to lh-totp-core

Thank you for your interest in contributing to **lh-totp-core**, an enterprise-grade, zero-dependency Two-Factor Authentication engine and MFA posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

We welcome contributions that improve cryptographic determinism, RFC compliance, timing side-channel resistance, MFA policy auditing, performance, and documentation.

---

## 1. Architectural Mandates & Standards

### Zero External Runtime Dependencies
`lh-totp-core` operates under a strict **Zero Runtime Dependencies** policy:
- All source code in `src/` must exclusively utilize native PHP 8.2+ core language features and standard system extensions:
  - `ext-hash`: Native cryptographic primitives including HMAC-SHA1, HMAC-SHA256, HMAC-SHA512, and PBKDF2.
  - `ext-json`: Canonical JSON parsing and serialization.
  - `ext-spl`: Autoloading, standard data structures, and exception hierarchy.
  - **CSPRNG**: `random_bytes()` and `random_int()` for secret, salt, and recovery code generation.
- **No Third-Party Runtime Packages**: `composer.json` must not declare any external production runtime dependencies in `require`.
- **Namespace Consistency**: All classes must reside under the `Logihertz\TotpCore\` namespace and comply with PSR-4 autoloading via `src/Autoloader.php`.
- **Strict Typing**: Every PHP file must begin with `declare(strict_types=1);`.
- **PHP 8.2 Compatibility**: Do not use features introduced in PHP 8.3+ (e.g., typed class constants like `public const string FOO = 'bar'`, which cause syntax errors in PHP 8.2). Use untyped constants `public const FOO = 'bar';`.

---

## 2. Local Development & Verification Workflow

Before submitting any code change or pull request, you must execute the full local verification pipeline:

### Step 1: Syntax Validation
Verify that every PHP file passes the PHP built-in syntax linter with zero errors:

```bash
find src bin tests -type f -exec php -l {} +
```

### Step 2: Zero-Dependency Test Suite
Run the deterministic test suite containing 85+ assertions covering RFC 4226 & RFC 6238 official vectors, Base32 encoding, timing resistance, replay protection, posture evaluation, and CLI execution:

```bash
php tests/run_tests.php
```
Ensure all assertions pass with a 100% success rate.

### Step 3: CLI Subprocess Smoke Testing
Verify that `bin/lh-totp` executes cleanly across its primary subcommands and formats:

```bash
# 1. Audit hardened configuration (expected exit code 0)
php bin/lh-totp scan fixtures/hardened_mfa_policy.json --format table

# 2. Audit vulnerable configuration with SARIF v2.1.0 export (expected exit code 1)
php bin/lh-totp scan fixtures/vulnerable_mfa_policy.json --format sarif

# 3. Generate a time-based one-time password
php bin/lh-totp generate --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

# 4. Build an otpauth:// provisioning URI
php bin/lh-totp provision --issuer "Logihertz Systems" --account "ops@logihertz.com"

# 5. Generate secure, hashed backup recovery codes
php bin/lh-totp backup-codes --count 8
```

---

## 3. RFC Compliance Guidelines

All authentication and hashing logic must adhere strictly to established IETF standards:

1. **RFC 4226 - HMAC-Based One-Time Password (HOTP)**:
   - Dynamic truncation must implement Section 5.4 exactly: extracting 4 bytes from offset $o = HS[19] \ \& \ \text{0x0F}$, masking the most significant bit with $\text{0x7F}$, and modulo $10^d$.
   - Must support official RFC 4226 Appendix D test vectors across counters $C = 0 \dots 9$.
   - Counter look-ahead verification must evaluate all candidate steps within the window $[C, C + W]$ in constant time without early exit.

2. **RFC 6238 - Time-Based One-Time Password (TOTP)**:
   - Time-step calculation: $T = \lfloor (t - T_0) / T_x \rfloor$ with $T_0 = 0$ and $T_x = 30$ seconds.
   - Must support official RFC 6238 Appendix B test vectors across timestamps `59`, `1111111109`, `1111111111`, `1234567890`, `2000000000`, `20000000000` for SHA1, SHA256, and SHA512.
   - Verification must evaluate all candidate drift steps $T + i$ for $i \in [-w, +w]$ using constant-time `hash_equals()`.
   - Replay protection must ensure no token is validated twice within its validity window.

3. **RFC 4648 - Base32 Encoding**:
   - Must implement constant-time alphabet indexing for `A-Z` and `2-7`.
   - Must support Base32 test vector `"12345678901234567890"` $\leftrightarrow$ `"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"`.

---

## 4. Guidelines for Adding or Modifying MFA Posture Rules (`LH-TOTP-001`..`010`)

When proposing a new audit rule or modifying existing detection logic in `src/TotpAuditor.php`:

1. **Deterministic Severity & Weighting**:
   Assign an objective severity, CWE mapping, and weight according to the Logihertz Posture Model:
   - `CRITICAL` (Weight: 25, e.g., Weak shared secret bits, disabled replay protection, plaintext secret storage)
   - `HIGH` (Weight: 10, e.g., Excessive drift window, missing lockout, weak code length, non-constant-time checks)
   - `MEDIUM` (Weight: 4, e.g., Deprecated SHA1 algorithm, insecure provisioning hygiene)
   - `LOW` (Weight: 1, e.g., Excessive backup code count, low backup code entropy)

2. **Mathematical Posture Score Invariant**:
   The posture score calculation must remain strictly deterministic:
   $$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

3. **Update Exporters & SARIF v2.1.0 Schemas**:
   Add the rule metadata to `TotpAuditor::RULE_METADATA` and verify that `Exporters::exportSarif()` correctly maps the rule ID, CWE tags, precision, and level (`error`, `warning`, `note`).

4. **Update Fixtures and Test Suite**:
   - Ensure `fixtures/hardened_mfa_policy.json` passes the new rule cleanly (0 findings, score 100).
   - Ensure `fixtures/vulnerable_mfa_policy.json` triggers the rule under policy violation conditions.
   - Add dedicated positive and negative assertions in `tests/run_tests.php`.

---

## 5. Pull Request & Commit Standards

- **Commit Message Format**: Follow Conventional Commits:
  - `feat: add support for WebAuthn credential metadata auditing`
  - `fix: resolve timing variance in HOTP look-ahead loop`
  - `docs: add RFC 6238 Appendix B test vector references in README`
  - `test: add assertions for PBKDF2 backup code verification`
- **Code Style & Formatting**:
  - 4 spaces indentation (no tabs in PHP source files).
  - Include the standard Logihertz Systems header comment banner at the top of every new PHP file:
    ```php
    <?php

    declare(strict_types=1);

    // ==============================================================================
    // Product:       lh-totp-core (bin/lh-totp)
    // Module:        Logihertz\TotpCore\...
    // Role:          ...
    // Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
    // Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
    // Contact:       ops@logihertz.com | https://logihertz.com/
    // License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
    // ==============================================================================
    ```
- **Attribution & Licensing**:
  All contributions are licensed under the **Apache License 2.0**. By submitting a pull request, you agree that your contribution is provided under the terms of the Apache License, Version 2.0, with copyright and attribution assigned to **Logihertz Systems (OPC) Private Limited**.

---

## 6. Communication & Questions

For architecture discussions, bug disclosures, or security inquiries:
- **Operations & Technical**: [ops@logihertz.com](mailto:ops@logihertz.com)
- **Security Vulnerabilities**: [security@logihertz.com](mailto:security@logihertz.com)
- **Executive Director**: Sameer Tawade (Creator, Founder, Director & Sole Developer)
