<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        Logihertz\TotpCore\TotpEngine
// Role:          RFC 6238 Time-Based One-Time Password Engine & Replay Guard
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use InvalidArgumentException;

/**
 * Implements RFC 6238 Time-Based One-Time Password (TOTP) generation,
 * constant-time verification across drift windows, token replay protection,
 * and Key Uri Format provisioning URI generation.
 */
class TotpEngine
{
    /** @var array<string, int> Replay cache of consumed token hashes => expiry timestamp */
    private static array $replayCache = [];

    private readonly HotpEngine $hotp;

    public function __construct(?HotpEngine $hotp = null)
    {
        $this->hotp = $hotp ?? new HotpEngine();
    }

    /**
     * Clear the static replay protection cache (useful for testing and session cycling).
     */
    public static function clearReplayCache(): void
    {
        self::$replayCache = [];
    }

    /**
     * Generate an RFC 6238 TOTP code from a Base32 shared secret.
     *
     * @param string $base32Secret RFC 4648 Base32 encoded shared secret.
     * @param int|null $timestamp Unix epoch seconds (defaults to time()).
     * @param int $period Time step Tx in seconds (default 30).
     * @param int $digits Output code length (6, 7, or 8 digits; default 6).
     * @param string $algo Hash algorithm ('sha1', 'sha256', 'sha512'; default 'sha256').
     * @return string Zero-padded TOTP code.
     * @throws InvalidArgumentException
     */
    public function generate(
        string $base32Secret,
        ?int $timestamp = null,
        int $period = 30,
        int $digits = 6,
        string $algo = 'sha256'
    ): string {
        $rawKey = Base32::decode($base32Secret);
        return $this->generateFromRawKey($rawKey, $timestamp, $period, $digits, $algo);
    }

    /**
     * Generate an RFC 6238 TOTP code directly from raw binary key bytes.
     *
     * @param string $rawKey Raw binary secret bytes.
     * @param int|null $timestamp Unix epoch seconds (defaults to time()).
     * @param int $period Time step Tx in seconds (default 30).
     * @param int $digits Output code length (6, 7, or 8 digits; default 6).
     * @param string $algo Hash algorithm ('sha1', 'sha256', 'sha512'; default 'sha256').
     * @return string Zero-padded TOTP code.
     * @throws InvalidArgumentException
     */
    public function generateFromRawKey(
        string $rawKey,
        ?int $timestamp = null,
        int $period = 30,
        int $digits = 6,
        string $algo = 'sha256'
    ): string {
        if ($period <= 0) {
            throw new InvalidArgumentException("Period must be a positive integer in seconds; given {$period}.");
        }

        $t = $timestamp ?? time();
        $counter = intdiv($t, $period);

        return $this->hotp->generateFromRawKey($rawKey, $counter, $digits, $algo);
    }

    /**
     * Verify an RFC 6238 TOTP token with constant-time evaluation across drift windows
     * and automatic replay protection against token reuse.
     *
     * @param string $base32Secret RFC 4648 Base32 shared secret.
     * @param string $otp User-submitted OTP code.
     * @param int|null $timestamp Reference timestamp (defaults to time()).
     * @param int $window Clock drift tolerance steps in [-window, +window] (default 1).
     * @param int $period Time step in seconds (default 30).
     * @param int $digits Expected code digits (default 6).
     * @param string $algo Hash digest algorithm (default 'sha256').
     * @param bool $enforceReplayProtection Whether to reject tokens replayed within the window.
     * @return array{valid: bool, drift_steps: ?int, replayed: bool, matched_step: ?int}
     */
    public function verify(
        string $base32Secret,
        string $otp,
        ?int $timestamp = null,
        int $window = 1,
        int $period = 30,
        int $digits = 6,
        string $algo = 'sha256',
        bool $enforceReplayProtection = true
    ): array {
        $rawKey = Base32::decode($base32Secret);
        $cleanOtp = trim($otp);
        $t = $timestamp ?? time();
        $centerStep = intdiv($t, $period);

        $matched = false;
        $matchedDrift = null;
        $matchedStep = null;

        // Constant-time traversal across [-window, +window] steps
        for ($i = -$window; $i <= $window; $i++) {
            $candidateStep = $centerStep + $i;
            $candidateOtp = $this->hotp->generateFromRawKey($rawKey, $candidateStep, $digits, $algo);

            $isMatch = hash_equals($candidateOtp, $cleanOtp);
            if ($isMatch && !$matched) {
                $matched = true;
                $matchedDrift = $i;
                $matchedStep = $candidateStep;
            }
        }

        if (!$matched) {
            return [
                'valid' => false,
                'drift_steps' => null,
                'replayed' => false,
                'matched_step' => null,
            ];
        }

        // Replay Protection Check
        $replayed = false;
        if ($enforceReplayProtection && $matchedStep !== null) {
            $this->pruneExpiredReplayCache($t);
            $cacheKey = hash('sha256', "{$base32Secret}:{$matchedStep}:{$cleanOtp}");

            if (isset(self::$replayCache[$cacheKey])) {
                $replayed = true;
                return [
                    'valid' => false,
                    'drift_steps' => $matchedDrift,
                    'replayed' => true,
                    'matched_step' => $matchedStep,
                ];
            }

            // Mark token as consumed until window expires
            $expiryTimestamp = ($matchedStep + $window + 1) * $period;
            self::$replayCache[$cacheKey] = $expiryTimestamp;
        }

        return [
            'valid' => true,
            'drift_steps' => $matchedDrift,
            'replayed' => $replayed,
            'matched_step' => $matchedStep,
        ];
    }

    /**
     * Build an RFC-compliant otpauth:// URI for mobile authenticator enrollment.
     *
     * @param string $issuer Organization or service provider name.
     * @param string $accountName User identifier or email address.
     * @param string $base32Secret RFC 4648 Base32 encoded secret.
     * @param string $algo Hash algorithm ('SHA1', 'SHA256', 'SHA512').
     * @param int $digits Code length (default 6).
     * @param int $period Time step in seconds (default 30).
     * @return string Validated otpauth:// URI string.
     */
    public function buildProvisioningUri(
        string $issuer,
        string $accountName,
        string $base32Secret,
        string $algo = 'SHA256',
        int $digits = 6,
        int $period = 30
    ): string {
        $cleanIssuer = trim($issuer);
        $cleanAccount = trim($accountName);
        $cleanSecret = strtoupper(rtrim($base32Secret, '='));

        $label = rawurlencode($cleanIssuer) . ':' . rawurlencode($cleanAccount);
        $query = http_build_query([
            'secret' => $cleanSecret,
            'issuer' => $cleanIssuer,
            'algorithm' => strtoupper($algo),
            'digits' => $digits,
            'period' => $period,
        ]);

        return "otpauth://totp/{$label}?{$query}";
    }

    /**
     * Render a text-based ASCII enrollment card for CLI terminals.
     *
     * @param string $provisioningUri The otpauth:// URI.
     * @param string $secret The Base32 shared secret.
     * @return string ASCII enrollment block.
     */
    public function renderEnrollmentCard(string $provisioningUri, string $secret): string
    {
        $out = [];
        $out[] = '┌──────────────────────────────────────────────────────────────────────────────┐';
        $out[] = '│                     MFA ENROLLMENT PROVISIONING CARD                         │';
        $out[] = '├──────────────────────────────────────────────────────────────────────────────┤';
        $out[] = sprintf('│ Shared Secret:   %-59s │', $secret);
        $out[] = '│ Authenticator:   Compatible with Google Authenticator, YubiKey & FreeOTP     │';
        $out[] = '├──────────────────────────────────────────────────────────────────────────────┤';
        $out[] = '│ Key URI:                                                                     │';

        // Wrap long URI into box width
        $chunks = str_split($provisioningUri, 72);
        foreach ($chunks as $chunk) {
            $out[] = sprintf('│   %-74s │', $chunk);
        }

        $out[] = '└──────────────────────────────────────────────────────────────────────────────┘';
        return implode("\n", $out) . "\n";
    }

    /**
     * Prune expired tokens from the static replay protection cache.
     */
    private function pruneExpiredReplayCache(int $currentTime): void
    {
        foreach (self::$replayCache as $key => $expiresAt) {
            if ($currentTime > $expiresAt) {
                unset(self::$replayCache[$key]);
            }
        }
    }
}
