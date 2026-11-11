<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        Logihertz\TotpCore\HotpEngine
// Role:          RFC 4226 HMAC-Based One-Time Password Engine
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use InvalidArgumentException;

/**
 * Implements RFC 4226 HMAC-Based One-Time Password (HOTP) calculation,
 * dynamic truncation, and constant-time look-ahead window verification.
 */
class HotpEngine
{
    public const SUPPORTED_ALGORITHMS = ['sha1', 'sha256', 'sha512'];

    /**
     * Generate an RFC 4226 HOTP value from a Base32 shared secret.
     *
     * @param string $base32Secret RFC 4648 Base32 encoded shared secret.
     * @param int $counter 64-bit moving counter C.
     * @param int $digits Output code length (6, 7, or 8 digits; default: 6).
     * @param string $algo HMAC digest algorithm ('sha1', 'sha256', or 'sha512').
     * @return string Zero-padded HOTP numeric code.
     * @throws InvalidArgumentException
     */
    public function generate(string $base32Secret, int $counter, int $digits = 6, string $algo = 'sha1'): string
    {
        $rawKey = Base32::decode($base32Secret);
        return $this->generateFromRawKey($rawKey, $counter, $digits, $algo);
    }

    /**
     * Generate an RFC 4226 HOTP value directly from raw binary key bytes.
     *
     * @param string $rawKey Raw binary secret key bytes.
     * @param int $counter 64-bit moving counter C.
     * @param int $digits Output code length (6, 7, or 8 digits; default: 6).
     * @param string $algo HMAC digest algorithm ('sha1', 'sha256', or 'sha512').
     * @return string Zero-padded HOTP numeric code.
     * @throws InvalidArgumentException
     */
    public function generateFromRawKey(string $rawKey, int $counter, int $digits = 6, string $algo = 'sha1'): string
    {
        if ($digits < 6 || $digits > 8) {
            throw new InvalidArgumentException("OTP length must be 6, 7, or 8 digits; requested {$digits}.");
        }

        $normalizedAlgo = strtolower($algo);
        if (!in_array($normalizedAlgo, self::SUPPORTED_ALGORITHMS, true)) {
            throw new InvalidArgumentException("Unsupported HMAC algorithm '{$algo}'. Supported: " . implode(', ', self::SUPPORTED_ALGORITHMS));
        }

        if ($counter < 0) {
            throw new InvalidArgumentException("Counter cannot be negative: {$counter}.");
        }

        // 1. Pack 64-bit counter as 8-byte big-endian binary string
        $binaryCounter = pack('J', $counter);

        // 2. Compute HMAC digest
        $hmac = hash_hmac($normalizedAlgo, $binaryCounter, $rawKey, true);

        // 3. RFC 4226 Section 5.4 Dynamic Truncation
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;

        $p = ((ord($hmac[$offset]) & 0x7F) << 24)
            | ((ord($hmac[$offset + 1]) & 0xFF) << 16)
            | ((ord($hmac[$offset + 2]) & 0xFF) << 8)
            | (ord($hmac[$offset + 3]) & 0xFF);

        // 4. Modulo 10^digits and left-pad with zeros
        $modulo = 10 ** $digits;
        $otp = (string) ($p % $modulo);

        return str_pad($otp, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Verify an HOTP token against a counter within a forward look-ahead window.
     * Evaluates all candidates in constant time to mitigate timing side-channels.
     *
     * @param string $base32Secret RFC 4648 Base32 encoded shared secret.
     * @param string $otp User-submitted OTP code.
     * @param int $counter Current server counter.
     * @param int $lookAheadWindow Forward window steps to evaluate (default 1).
     * @param int $digits Expected code length (default 6).
     * @param string $algo HMAC algorithm (default 'sha1').
     * @return array{valid: bool, matched_counter: ?int, next_counter: ?int}
     */
    public function verify(
        string $base32Secret,
        string $otp,
        int $counter,
        int $lookAheadWindow = 1,
        int $digits = 6,
        string $algo = 'sha1'
    ): array {
        $rawKey = Base32::decode($base32Secret);
        $cleanOtp = trim($otp);

        $matched = false;
        $matchedCounter = null;

        // Constant-time traversal across look-ahead window without short-circuit return
        for ($w = 0; $w <= $lookAheadWindow; $w++) {
            $candidateCounter = $counter + $w;
            $expectedOtp = $this->generateFromRawKey($rawKey, $candidateCounter, $digits, $algo);

            $isMatch = hash_equals($expectedOtp, $cleanOtp);
            if ($isMatch && !$matched) {
                $matched = true;
                $matchedCounter = $candidateCounter;
            }
        }

        return [
            'valid' => $matched,
            'matched_counter' => $matchedCounter,
            'next_counter' => $matchedCounter !== null ? $matchedCounter + 1 : null,
        ];
    }
}
