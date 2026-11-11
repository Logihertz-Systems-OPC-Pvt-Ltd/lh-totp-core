<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        Logihertz\TotpCore\TotpAuditor
// Role:          10-Rule Deterministic MFA & TOTP Posture Security Engine
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use InvalidArgumentException;
use JsonException;

/**
 * Finding model representing a single evaluated MFA/TOTP policy violation.
 */
class AuditFinding
{
    public function __construct(
        public readonly string $ruleId,
        public readonly string $severity,
        public readonly string $cwe,
        public readonly string $title,
        public readonly string $description,
        public readonly string $recommendation,
        public readonly ?string $evidence = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'severity' => $this->severity,
            'cwe' => $this->cwe,
            'title' => $this->title,
            'description' => $this->description,
            'recommendation' => $this->recommendation,
            'evidence' => $this->evidence,
        ];
    }
}

/**
 * Comprehensive audit result containing findings, summary metrics, and posture score.
 */
class AuditResult
{
    /**
     * @param string $target Target path or identifier.
     * @param string $targetType "policy_manifest" or "runtime".
     * @param string $timestamp ISO 8601 timestamp.
     * @param int $postureScore Normalized posture score (0-100).
     * @param array<AuditFinding> $findings List of detected rule findings.
     * @param array{total_findings: int, critical: int, high: int, medium: int, low: int} $summary
     */
    public function __construct(
        public readonly string $target,
        public readonly string $targetType,
        public readonly string $timestamp,
        public readonly int $postureScore,
        public readonly array $findings,
        public readonly array $summary,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'target' => $this->target,
            'target_type' => $this->targetType,
            'timestamp' => $this->timestamp,
            'posture_score' => $this->postureScore,
            'summary' => $this->summary,
            'findings' => array_map(static fn(AuditFinding $f): array => $f->toArray(), $this->findings),
        ];
    }
}

/**
 * Deterministic multi-factor authentication (MFA) and TOTP policy posture auditor
 * evaluating security manifests against rules LH-TOTP-001 through LH-TOTP-010.
 */
class TotpAuditor
{
    /** @var array<string, array{severity: string, cwe: string, title: string, weight: int}> */
    public const RULE_METADATA = [
        'LH-TOTP-001' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-326',
            'title' => 'Insufficient shared secret bit length (< 128 bits) or low entropy seed',
            'weight' => 25,
        ],
        'LH-TOTP-002' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-294',
            'title' => 'OTP token replay protection disabled, permitting duplicate verification',
            'weight' => 25,
        ],
        'LH-TOTP-003' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-307',
            'title' => 'Excessive clock-drift verification tolerance window (> 2 steps)',
            'weight' => 10,
        ],
        'LH-TOTP-004' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-307',
            'title' => 'Missing or weak MFA verification rate limiting and account lockout policy',
            'weight' => 10,
        ],
        'LH-TOTP-005' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-330',
            'title' => 'Excessive TOTP time-step period (> 60s) or weak code length (< 6 digits)',
            'weight' => 10,
        ],
        'LH-TOTP-006' => [
            'severity' => 'MEDIUM',
            'cwe' => 'CWE-328',
            'title' => 'Deprecated SHA1 HMAC digest algorithm configured instead of SHA256/SHA512',
            'weight' => 4,
        ],
        'LH-TOTP-007' => [
            'severity' => 'CRITICAL',
            'cwe' => 'CWE-312',
            'title' => 'Plaintext TOTP secret storage at rest or unhashed backup recovery codes',
            'weight' => 25,
        ],
        'LH-TOTP-008' => [
            'severity' => 'HIGH',
            'cwe' => 'CWE-208',
            'title' => 'Non-constant-time OTP verification exposing timing side-channel attacks',
            'weight' => 10,
        ],
        'LH-TOTP-009' => [
            'severity' => 'MEDIUM',
            'cwe' => 'CWE-319',
            'title' => 'Insecure otpauth:// provisioning hygiene, missing TLS, or plaintext logging',
            'weight' => 4,
        ],
        'LH-TOTP-010' => [
            'severity' => 'LOW',
            'cwe' => 'CWE-755',
            'title' => 'Excessive backup code inventory (> 10) or insufficient recovery code entropy (< 64 bits)',
            'weight' => 1,
        ],
    ];

    /**
     * Audit an MFA policy JSON file against all 10 detection rules.
     *
     * @param string $filePath Path to JSON manifest file.
     * @return AuditResult
     * @throws InvalidArgumentException
     */
    public function auditFile(string $filePath): AuditResult
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new InvalidArgumentException("Policy target is not a readable file: {$filePath}");
        }

        $raw = file_get_contents($filePath);
        if ($raw === false) {
            throw new InvalidArgumentException("Failed to read file: {$filePath}");
        }

        try {
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($data)) {
                throw new InvalidArgumentException('Policy file must contain a valid JSON object.');
            }
            return $this->auditPolicy($data, $filePath);
        } catch (JsonException $e) {
            throw new InvalidArgumentException("Malformed JSON policy manifest: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Audit an MFA configuration array against rules LH-TOTP-001 through LH-TOTP-010.
     *
     * @param array<string, mixed> $policy Policy configuration array.
     * @param string $target Target name for reporting.
     * @return AuditResult
     */
    public function auditPolicy(array $policy, string $target = 'mfa_policy.json'): AuditResult
    {
        $findings = [];

        // LH-TOTP-001 (CRITICAL, 25, CWE-326): Shared secret bit length < 128 or low entropy
        $secretBits = (int) ($policy['secret_bits'] ?? 256);
        $shannonEntropy = (float) ($policy['shannon_entropy'] ?? 4.0);

        if ($secretBits < 128 || $shannonEntropy < 3.5) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-001',
                severity: 'CRITICAL',
                cwe: 'CWE-326',
                title: self::RULE_METADATA['LH-TOTP-001']['title'],
                description: 'Shared secret seed does not meet the minimum 128-bit RFC 4226 requirement or exhibits insufficient Shannon entropy.',
                recommendation: 'Generate secrets with at least 16 bytes (128 bits; recommended 256 bits) using CSPRNG random_bytes().',
                evidence: sprintf('secret_bits=%d (min: 128), shannon_entropy=%.2f (min: 3.50)', $secretBits, $shannonEntropy)
            );
        }

        // LH-TOTP-002 (CRITICAL, 25, CWE-294): Replay protection disabled
        $replayProtection = (bool) ($policy['replay_protection_enabled'] ?? false);
        if (!$replayProtection) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-002',
                severity: 'CRITICAL',
                cwe: 'CWE-294',
                title: self::RULE_METADATA['LH-TOTP-002']['title'],
                description: 'Token replay cache is disabled, allowing an intercepted OTP to be reused within its valid time window.',
                recommendation: 'Enable replay_protection_enabled: true and record consumed tokens in an in-memory/cache store.',
                evidence: 'replay_protection_enabled: false'
            );
        }

        // LH-TOTP-003 (HIGH, 10, CWE-307): Excessive clock-drift verification tolerance window (> 2 steps)
        $windowSteps = (int) ($policy['window_steps'] ?? 1);
        if ($windowSteps > 2) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-003',
                severity: 'HIGH',
                cwe: 'CWE-307',
                title: self::RULE_METADATA['LH-TOTP-003']['title'],
                description: 'Verification acceptance window exceeds safe clock drift bounds, expanding the attack surface for guessing attacks.',
                recommendation: 'Configure window_steps to 1 (or at most 2) steps per RFC 6238 Section 5.2 recommendation.',
                evidence: sprintf('window_steps=%d (max recommended: 2)', $windowSteps)
            );
        }

        // LH-TOTP-004 (HIGH, 10, CWE-307): Missing or weak MFA verification rate limiting/lockout
        $lockoutEnabled = (bool) ($policy['lockout_enabled'] ?? true);
        $maxAttempts = (int) ($policy['max_failed_attempts'] ?? 5);
        $lockoutSecs = (int) ($policy['lockout_duration_seconds'] ?? 300);

        if (!$lockoutEnabled || $maxAttempts > 5 || $lockoutSecs < 300) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-004',
                severity: 'HIGH',
                cwe: 'CWE-307',
                title: self::RULE_METADATA['LH-TOTP-004']['title'],
                description: 'MFA brute-force protection is absent or insufficiently restrictive against automated OTP guessing.',
                recommendation: 'Enforce lockout_enabled: true, max_failed_attempts <= 5, and lockout_duration_seconds >= 300.',
                evidence: sprintf('lockout_enabled=%s, max_attempts=%d, lockout_duration=%ds', $lockoutEnabled ? 'true' : 'false', $maxAttempts, $lockoutSecs)
            );
        }

        // LH-TOTP-005 (HIGH, 10, CWE-330): Excessive time period (> 60s) or weak code length (< 6 digits)
        $period = (int) ($policy['period_seconds'] ?? 30);
        $digits = (int) ($policy['digits'] ?? 6);

        if ($period > 60 || $digits < 6) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-005',
                severity: 'HIGH',
                cwe: 'CWE-330',
                title: self::RULE_METADATA['LH-TOTP-005']['title'],
                description: 'TOTP time-step period exceeds safe limits or code length provides insufficient search space.',
                recommendation: 'Configure period_seconds to 30 (or max 60) and digits to 6 or 8.',
                evidence: sprintf('period_seconds=%d (max: 60), digits=%d (min: 6)', $period, $digits)
            );
        }

        // LH-TOTP-006 (MEDIUM, 4, CWE-328): Deprecated SHA1 HMAC digest algorithm configured
        $algorithm = strtoupper(trim((string) ($policy['algorithm'] ?? 'SHA256')));
        if ($algorithm === 'SHA1' || $algorithm === 'SHA-1') {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-006',
                severity: 'MEDIUM',
                cwe: 'CWE-328',
                title: self::RULE_METADATA['LH-TOTP-006']['title'],
                description: 'Policy specifies legacy SHA1 digest algorithm for HMAC one-time password generation.',
                recommendation: 'Upgrade to algorithm: "SHA256" or "SHA512" per modern NIST and RFC 6238 guidelines.',
                evidence: sprintf('algorithm: "%s"', $algorithm)
            );
        }

        // LH-TOTP-007 (CRITICAL, 25, CWE-312): Plaintext secret storage or unhashed backup codes
        $encryptSecrets = (bool) ($policy['encrypt_secret_at_rest'] ?? true);
        $hashBackupCodes = (bool) ($policy['hash_backup_codes'] ?? true);

        if (!$encryptSecrets || !$hashBackupCodes) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-007',
                severity: 'CRITICAL',
                cwe: 'CWE-312',
                title: self::RULE_METADATA['LH-TOTP-007']['title'],
                description: 'TOTP shared secrets or emergency backup codes are stored in plaintext at rest.',
                recommendation: 'Set encrypt_secret_at_rest: true (using AES-GCM or KMS) and hash_backup_codes: true (using PBKDF2/Argon2id).',
                evidence: sprintf('encrypt_secret_at_rest=%s, hash_backup_codes=%s', $encryptSecrets ? 'true' : 'false', $hashBackupCodes ? 'true' : 'false')
            );
        }

        // LH-TOTP-008 (HIGH, 10, CWE-208): Non-constant-time verification
        $constantTime = (bool) ($policy['constant_time_verification'] ?? true);
        if (!$constantTime) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-008',
                severity: 'HIGH',
                cwe: 'CWE-208',
                title: self::RULE_METADATA['LH-TOTP-008']['title'],
                description: 'OTP string comparison uses variable-time equality operators, vulnerable to microarchitectural timing attacks.',
                recommendation: 'Enforce constant_time_verification: true using PHP hash_equals() across all comparison routines.',
                evidence: 'constant_time_verification: false'
            );
        }

        // LH-TOTP-009 (MEDIUM, 4, CWE-319): Insecure otpauth:// provisioning hygiene
        $requireTls = (bool) ($policy['require_tls_enrollment'] ?? true);
        $issuer = trim((string) ($policy['issuer'] ?? ''));
        $logUri = (bool) ($policy['log_provisioning_uri'] ?? false);

        if (!$requireTls || $issuer === '' || $logUri) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-009',
                severity: 'MEDIUM',
                cwe: 'CWE-319',
                title: self::RULE_METADATA['LH-TOTP-009']['title'],
                description: 'MFA enrollment provisioning exposes seeds via cleartext transport, lacks issuer name, or logs provisioning URIs.',
                recommendation: 'Enforce require_tls_enrollment: true, provide a non-empty issuer, and set log_provisioning_uri: false.',
                evidence: sprintf('require_tls=%s, issuer="%s", log_uri=%s', $requireTls ? 'true' : 'false', $issuer, $logUri ? 'true' : 'false')
            );
        }

        // LH-TOTP-010 (LOW, 1, CWE-755): Excessive backup code count (> 10) or insufficient entropy (< 64 bits)
        $codeCount = (int) ($policy['backup_code_count'] ?? 8);
        $codeBits = (int) ($policy['backup_code_bits'] ?? 80);

        if ($codeCount > 10 || $codeBits < 64) {
            $findings[] = new AuditFinding(
                ruleId: 'LH-TOTP-010',
                severity: 'LOW',
                cwe: 'CWE-755',
                title: self::RULE_METADATA['LH-TOTP-010']['title'],
                description: 'Backup recovery code pool exceeds recommended limits or individual codes lack sufficient cryptographic entropy.',
                recommendation: 'Issue at most 10 backup codes with at least 64 bits of entropy (e.g., 16 characters from a 32-character alphabet).',
                evidence: sprintf('backup_code_count=%d (max: 10), backup_code_bits=%d (min: 64)', $codeCount, $codeBits)
            );
        }

        // Compute summary metrics and posture score
        $critical = 0;
        $high = 0;
        $medium = 0;
        $low = 0;

        foreach ($findings as $f) {
            match ($f->severity) {
                'CRITICAL' => $critical++,
                'HIGH' => $high++,
                'MEDIUM' => $medium++,
                'LOW' => $low++,
                default => null,
            };
        }

        // S_posture = max(0, 100 - (25*c_CRITICAL + 10*c_HIGH + 4*c_MEDIUM + 1*c_LOW))
        $deduction = (25 * $critical) + (10 * $high) + (4 * $medium) + (1 * $low);
        $postureScore = max(0, 100 - $deduction);

        $summary = [
            'total_findings' => count($findings),
            'critical' => $critical,
            'high' => $high,
            'medium' => $medium,
            'low' => $low,
        ];

        return new AuditResult(
            target: $target,
            targetType: 'policy_manifest',
            timestamp: gmdate('Y-m-d\TH:i:s\Z'),
            postureScore: $postureScore,
            findings: $findings,
            summary: $summary,
        );
    }
}
